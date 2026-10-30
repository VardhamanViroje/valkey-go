package valkeygcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
)

const (
	helloOK         = "%3\r\n+server\r\n+valkey\r\n+proto\r\n:3\r\n+version\r\n+8.0.0\r\n"
	iamExhausted    = "-ERR (ERR_IAM_EXHAUSTED) Memorystore IAM authentication backend quota exceeded.\r\n"
	clusterDisabled = "-ERR This instance has cluster support disabled\r\n"
)

// fakeValkey is a RESP server on loopback. reply answers one command on connection conn
// (numbered from 1); drop closes the connection after that reply.
type fakeValkey struct {
	ln    net.Listener
	conns atomic.Int64
	reply func(conn int64, args []string) (resp string, drop bool)
}

func newFakeValkey(t *testing.T, reply func(conn int64, args []string) (string, bool)) *fakeValkey {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeValkey{ln: ln, reply: reply}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id := f.conns.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				f.serve(c, id)
			}()
		}
	}()
	return f
}

func (f *fakeValkey) addr() string { return f.ln.Addr().String() }

func (f *fakeValkey) serve(c net.Conn, id int64) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		resp, drop := f.reply(id, args)
		if _, err := io.WriteString(c, resp); err != nil || drop {
			return
		}
	}
}

func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected %q", line)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadString('\n'); err != nil { // $len
			return nil, err
		}
		arg, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimSuffix(arg, "\r\n"))
	}
	return args, nil
}

// standaloneReply answers like a cluster-disabled Valkey node.
func standaloneReply(_ int64, args []string) (string, bool) {
	switch strings.ToUpper(args[0]) {
	case "HELLO":
		return helloOK, false
	case "CLUSTER":
		return clusterDisabled, false
	case "PING":
		return "+PONG\r\n", false
	case "GET":
		return "$2\r\nok\r\n", false
	}
	return "+OK\r\n", false
}

// iamOptions are Options with a static IAM token and TLS off on purpose, for a
// cluster-disabled node. extra comes last, so it can override them.
func iamOptions(extra ...Option) []Option {
	return append([]Option{
		WithTopology(TopologyClusterDisabled),
		WithIAMOptions(staticIAM()),
		WithTLS(TLSOptions{Mode: TLSDisabled}),
	}, extra...)
}

// When Memorystore rejects the handshake with an IAM backend error (ERR_IAM_EXHAUSTED or
// ERR_IAM_OTHER), NewClient retries with exponential backoff, since valkey-go doesn't
// retry that reply. Here the third connection succeeds.
func TestNewClient_RetriesIAMBackendErrors(t *testing.T) {
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if strings.EqualFold(args[0], "HELLO") && conn <= 2 {
			return iamExhausted, false
		}
		return standaloneReply(conn, args)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewClient(ctx, initOption(srv.addr()), iamOptions()...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	if n := srv.conns.Load(); n < 3 {
		t.Fatalf("connections = %d, want at least 3 (two throttled handshakes, then success)", n)
	}
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		t.Fatal(err)
	}
}

// The retries of IAM backend errors stop when NewClient's ctx ends; the error keeps the IAM
// reply and wraps the ctx error.
func TestNewClient_IAMRetriesStopAtDeadline(t *testing.T) {
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if strings.EqualFold(args[0], "HELLO") {
			return iamExhausted, false
		}
		return standaloneReply(conn, args)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewClient(ctx, initOption(srv.addr()), iamOptions()...)
	if err == nil || !strings.Contains(err.Error(), "ERR_IAM_EXHAUSTED") || !strings.Contains(err.Error(), "gave up after") ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the IAM error after giving up at the deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("took %v, want about the 700ms deadline", elapsed)
	}
	if n := srv.conns.Load(); n < 2 {
		t.Fatalf("connections = %d, want at least 2 (retried)", n)
	}
}

// Handshake errors other than the IAM backend errors, such as WRONGPASS, are returned at
// once, without a retry.
func TestNewClient_OtherHandshakeErrorsNotRetried(t *testing.T) {
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if strings.EqualFold(args[0], "HELLO") {
			return "-WRONGPASS invalid username-password pair or user is disabled\r\n", false
		}
		return standaloneReply(conn, args)
	})
	_, err := NewClient(context.Background(), initOption(srv.addr()), iamOptions()...)
	if err == nil || !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("got %v, want WRONGPASS", err)
	}
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
}

// valkey-go sends CLIENT TRACKING on every new connection unless ClientOption.DisableCache
// is set. When an ACL rule refuses it, the error names the ACL rule to change and still
// wraps valkey.ErrNoCache.
func TestNewClient_ClientTrackingNOPERMHint(t *testing.T) {
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if len(args) > 1 && strings.EqualFold(args[0], "CLIENT") && strings.EqualFold(args[1], "TRACKING") {
			return "-NOPERM User default has no permissions to run the 'client|tracking' command\r\n", false
		}
		return standaloneReply(conn, args)
	})
	_, err := NewClient(context.Background(), initOption(srv.addr()), iamOptions()...)
	if err == nil || !strings.Contains(err.Error(), `ACL rule for user "default" must allow CLIENT TRACKING (+client|tracking)`) ||
		!errors.Is(err, valkey.ErrNoCache) {
		t.Fatalf("got %v, want the ACL hint wrapping ErrNoCache", err)
	}
}

// valkey-go quietly falls back to a single-node client when CLUSTER SHARDS fails, for
// example because an ACL rule denies it. With TopologyCluster, NewClient fails instead and
// names the ACL permission to add; ForceSingleClient and TopologyAuto keep the fallback.
func TestNewClient_ClusterFallbackRejected(t *testing.T) {
	const noperm = "-NOPERM User default has no permissions to run the 'cluster|shards' command\r\n"
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if strings.EqualFold(args[0], "CLUSTER") {
			return noperm, false
		}
		return standaloneReply(conn, args)
	})
	cluster := iamOptions(WithTopology(TopologyCluster))
	_, err := NewClient(context.Background(), initOption(srv.addr()), cluster...)
	if err == nil || !strings.Contains(err.Error(), "fell back to a single-node client") ||
		!strings.Contains(err.Error(), "+cluster|shards") || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("got %v, want the cluster fallback error with the CLUSTER SHARDS reply", err)
	}

	// ForceSingleClient is the caller's choice: no error.
	option := initOption(srv.addr())
	option.ForceSingleClient = true
	client, err := NewClient(context.Background(), option, cluster...)
	if err != nil {
		t.Fatalf("ForceSingleClient: %v", err)
	}
	client.Close()

	// The check needs TopologyCluster: with TopologyAuto, what valkey-go detects stands.
	client, err = NewClient(context.Background(), initOption(srv.addr()), iamOptions(WithTopology(TopologyAuto))...)
	if err != nil {
		t.Fatalf("TopologyAuto: %v", err)
	}
	if mode := client.Mode(); mode != valkey.ClientModeStandalone {
		t.Errorf("TopologyAuto: mode = %v, want the single-node client valkey-go fell back to", mode)
	}
	client.Close()
}

// OnAuth reports each credential hand-out with the node address, the username and a
// fingerprint of the token, never the token itself. Plaintext is set because TLS is off.
func TestNewClient_OnAuthEvents(t *testing.T) {
	srv := newFakeValkey(t, standaloneReply)
	var mu sync.Mutex
	var events []AuthEvent
	onAuth := OnAuth(func(ev AuthEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})
	client, err := NewClient(context.Background(), initOption(srv.addr()), iamOptions(onAuth)...)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("no AuthEvent")
	}
	ev := events[0]
	if ev.Address != srv.addr() || ev.Username != DefaultIAMUsername || ev.Fingerprint != fingerprint("iam-token") ||
		ev.RefreshAfter.IsZero() || ev.Fallback || ev.Err != nil || !ev.Plaintext {
		t.Fatalf("event = %+v", ev)
	}
}

// The AuthEvent fingerprint is keyed, so a logged value can't be used to check guesses of
// the token offline the way its plain SHA-256 could; it still tells tokens apart.
func TestFingerprint_Keyed(t *testing.T) {
	fp := fingerprint("tok-1")
	plain := sha256.Sum256([]byte("tok-1"))
	switch {
	case len(fp) != 12:
		t.Fatalf("fingerprint %q: want 12 hex digits", fp)
	case fp == hex.EncodeToString(plain[:6]):
		t.Fatal("fingerprint is the token's plain SHA-256")
	case fp != fingerprint("tok-1"):
		t.Fatal("the same token got a different fingerprint")
	case fp == fingerprint("tok-2"):
		t.Fatal("a rotated token kept its fingerprint")
	}
}

// When a token fetch fails and the last good token is handed out instead, the AuthEvent
// has Fallback set and the same fingerprint. Token Auth reports events too, with the
// "default" user when TokenAuthOptions.Username is empty.
func TestOnAuth_FallbackAndError(t *testing.T) {
	var fail atomic.Bool
	src := tokenSourceFunc(func() (*oauth2.Token, error) {
		if fail.Load() {
			return nil, errors.New("metadata server down")
		}
		return &oauth2.Token{AccessToken: "t1", Expiry: time.Now().Add(time.Hour)}, nil
	})
	var got []AuthEvent
	p, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: src,
		OnAuth:            func(ev AuthEvent) { got = append(got, ev) },
		RefreshBuffer:     2 * time.Hour, // every call refetches
	})
	if err != nil {
		t.Fatal(err)
	}
	fn := p.AuthCredentialsFn()
	if _, err := fn(valkey.AuthCredentialsContext{}); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err := fn(valkey.AuthCredentialsContext{}); err != nil {
		t.Fatal(err) // the fetch fails, but the last token that worked is handed out instead
	}
	if len(got) != 2 || got[0].Fallback || got[0].Fingerprint == "" || !got[1].Fallback || got[1].Fingerprint != got[0].Fingerprint {
		t.Fatalf("events = %+v", got)
	}

	tp, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Token: "tok", OnAuth: func(ev AuthEvent) { got = append(got, ev) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tp.AuthCredentialsFn()(valkey.AuthCredentialsContext{}); err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Username != "default" || last.Fingerprint == "" || last.Plaintext {
		t.Fatalf("Token Auth event = %+v", last)
	}
}

// IAM and Token Auth credentials aren't sent in plaintext unless the caller turns TLS off
// on purpose, or the instance has in-transit encryption disabled.
func TestResolve_PlaintextCredentials(t *testing.T) {
	ca := newTestCA(t, "ca")
	noTLSInstance := clusterInstance(memorystorepb.Instance_IAM_AUTH)
	withTLSConfig := initOption("10.0.0.15:6379")
	withTLSConfig.TLSConfig = &tls.Config{}
	withPassword := initOption("10.0.0.15:6379")
	withPassword.Password = "p"
	iam, token := WithIAMOptions(staticIAM()), WithTokenAuth(TokenAuthOptions{Token: "t"})
	cases := []struct {
		name    string
		option  valkey.ClientOption
		opts    []Option
		reader  readerFactory
		refused bool
	}{
		{"IAM, no TLS option", initOption("10.0.0.15:6379"), []Option{iam}, noReader(t), true},
		{"IAM with ADC, no TLS option", initOption("10.0.0.15:6379"), []Option{WithDefaultIAM()}, noReader(t), true},
		{"Token Auth, no TLS option", initOption("10.0.0.2:6379"), []Option{token}, noReader(t), true},
		{"IAM, TLS off on purpose", initOption("10.0.0.15:6379"), []Option{iam, WithTLS(TLSOptions{Mode: TLSDisabled})}, noReader(t), false},
		{"IAM with a CA", initOption("10.0.0.15:6379"), []Option{iam, WithTLS(TLSOptions{CAPEM: ca.pem})}, noReader(t), false},
		{"IAM with a caller TLSConfig", withTLSConfig, []Option{iam}, noReader(t), false},
		{"Token Auth with a caller TLSConfig", withTLSConfig, []Option{token}, noReader(t), false},
		{"auth disabled", initOption("10.0.0.15:6379"), nil, noReader(t), false},
		{"caller password", withPassword, nil, noReader(t), false},
		{"instance without TLS decides", valkey.ClientOption{}, []Option{WithInstance(testInstance), iam}, (&fakeReader{inst: noTLSInstance}).factory(), false},
	}
	for _, c := range cases {
		_, err := resolveWith(c.option, c.reader, c.opts...)
		if refused := err != nil && strings.Contains(err.Error(), "refusing to send"); refused != c.refused {
			t.Errorf("%s: got %v, want refused=%v", c.name, err, c.refused)
		}
		if c.refused && err != nil && !strings.Contains(err.Error(), "pass WithTLS") {
			t.Errorf("%s: %v does not say how to pass TLS options", c.name, err)
		}
		if !c.refused && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
	}
}

func TestDialGate(t *testing.T) {
	g := &dialGate{backoff: func(n int) time.Duration { return time.Duration(n+1) * time.Second }}
	g.handshake(handshakeIAMError)
	if d := g.delay(); d != 0 {
		t.Fatalf("delay before the first successful handshake = %v, want 0", d)
	}
	g.handshake(handshakeOK)
	g.handshake(handshakeIAMError)
	g.handshake(handshakeIAMError)
	if d := g.delay(); d != 2*time.Second {
		t.Fatalf("delay after 2 IAM errors = %v, want backoff(1) = 2s", d)
	}
	g.handshake(handshakeOther) // WRONGPASS and the like don't change the count
	if d := g.delay(); d != 2*time.Second {
		t.Fatalf("delay after another error = %v, want unchanged", d)
	}
	g.handshake(handshakeOK)
	if d := g.delay(); d != 0 {
		t.Fatalf("delay after a successful handshake = %v, want 0", d)
	}
	// The real schedule stays within the IAM cap.
	g = &dialGate{}
	g.handshake(handshakeOK)
	for i := 0; i < 30; i++ {
		g.handshake(handshakeIAMError)
	}
	if d := g.delay(); d <= 0 || d > iamBackoffCap {
		t.Fatalf("delay = %v, want (0, %v]", d, iamBackoffCap)
	}
}

func TestGatedConnPeek(t *testing.T) {
	cases := []struct {
		chunks []string
		want   int // failures after the reply; -1: success (armed, 0 failures)
	}{
		{[]string{helloOK}, -1},
		{[]string{"-ERR (ERR_IAM_", "EXHAUSTED) quota exceeded.\r\n"}, 1},
		{[]string{"-ERR (ERR_IAM_OTHER) backend error.\r\n+ignored\r\n"}, 1},
		{[]string{"-WRONGPASS invalid\r\n"}, 0},
	}
	for i, c := range cases {
		g := &dialGate{}
		conn := &gatedConn{Conn: &chunkConn{chunks: c.chunks}, gate: g}
		buf := make([]byte, 64)
		for range c.chunks {
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}
		}
		g.mu.Lock()
		failures := g.failures
		g.mu.Unlock()
		if c.want == -1 {
			if !g.armed.Load() || failures != 0 {
				t.Errorf("case %d: armed=%v failures=%d, want a recorded success", i, g.armed.Load(), failures)
			}
		} else if failures != c.want || g.armed.Load() {
			t.Errorf("case %d: armed=%v failures=%d, want failures=%d", i, g.armed.Load(), failures, c.want)
		}
		if !conn.seen {
			t.Errorf("case %d: first reply not complete", i)
		}
	}
}

// chunkConn returns one chunk per Read.
type chunkConn struct {
	net.Conn
	chunks []string
}

func (c *chunkConn) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[0])
	c.chunks = c.chunks[1:]
	return n, nil
}

// After a re-dial's HELLO is rejected with an IAM backend error, the dial gate makes the
// next dial wait for the backoff instead of following the request rate; a successful
// handshake clears the delay.
func TestDialGate_SpacesOutRedials(t *testing.T) {
	var dropFirst atomic.Bool
	dropFirst.Store(true)
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		switch {
		case strings.EqualFold(args[0], "HELLO") && conn == 2:
			return iamExhausted, false
		case strings.EqualFold(args[0], "GET") && conn == 1 && dropFirst.CompareAndSwap(true, false):
			return "$2\r\nok\r\n", true // the reply arrives, then the connection drops
		}
		return standaloneReply(conn, args)
	})
	const wait = 300 * time.Millisecond
	g := &dialGate{backoff: func(int) time.Duration { return wait }}
	opt := valkey.ClientOption{
		InitAddress:       []string{srv.addr()},
		ForceSingleClient: true,
		PipelineMultiplex: -1, // one connection, so the test controls which one a command uses
		DisableCache:      true,
		AuthCredentialsFn: func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
			return valkey.AuthCredentials{Password: "tok"}, nil
		},
		DialCtxFn: gatedDialer(nil, g, false),
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	get := func() error { return client.Do(ctx, client.B().Get().Key("k").Build()).Error() }
	if err := get(); err != nil { // served by connection 1, which then drops
		t.Fatal(err)
	}
	if err := get(); err == nil || !strings.Contains(err.Error(), "ERR_IAM_EXHAUSTED") { // re-dial 2 is throttled
		t.Fatalf("got %v, want ERR_IAM_EXHAUSTED from the throttled re-dial", err)
	}
	start := time.Now()
	if err := get(); err != nil { // re-dial 3 waits for the gate, then works
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < wait {
		t.Fatalf("re-dial after the IAM error took %v, want at least the %v backoff", elapsed, wait)
	}
	if d := g.delay(); d != 0 {
		t.Fatalf("delay after the successful handshake = %v, want 0", d)
	}
}

func TestGatedDialer_StopsWaitingWhenCtxEnds(t *testing.T) {
	g := &dialGate{backoff: func(int) time.Duration { return time.Hour }}
	g.handshake(handshakeOK)
	g.handshake(handshakeIAMError)
	dialed := false
	dial := gatedDialer(func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unreachable")
	}, g, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := dial(ctx, "10.0.0.1:6379", &net.Dialer{}, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "IAM backend error") || dialed {
		t.Fatalf("got %v (dialed=%v), want the ctx error before dialing", err, dialed)
	}
}

// installDialGate keeps a caller's dialer underneath the gate.
func TestInstallDialGate_KeepsCallerDialer(t *testing.T) {
	ctxCalls, plainCalls := 0, 0
	errDial := errors.New("dial")
	opt := valkey.ClientOption{DialCtxFn: func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
		ctxCalls++
		return nil, errDial
	}}
	installDialGate(&opt)
	if _, err := opt.DialCtxFn(context.Background(), "a:1", &net.Dialer{}, nil); !errors.Is(err, errDial) || ctxCalls != 1 {
		t.Fatalf("DialCtxFn: got %v, calls %d", err, ctxCalls)
	}
	opt = valkey.ClientOption{}
	opt.DialFn = func(string, *net.Dialer, *tls.Config) (net.Conn, error) {
		plainCalls++
		return nil, errDial
	}
	installDialGate(&opt)
	if _, err := opt.DialCtxFn(context.Background(), "a:1", &net.Dialer{}, nil); !errors.Is(err, errDial) || plainCalls != 1 {
		t.Fatalf("DialFn: got %v, calls %d", err, plainCalls)
	}
}

// A primary endpoint alone, without a reader endpoint, gives a working client: no empty
// reader address is configured, which valkey-go would fail to dial. valkey-go tries cluster
// mode first, finds it disabled and falls back to a single-node client, also with
// WithTopology(TopologyClusterDisabled), which only leaves out the cluster defaults.
func TestNewClient_PrimaryEndpointOnly(t *testing.T) {
	srv := newFakeValkey(t, standaloneReply)
	for _, topology := range []Topology{TopologyAuto, TopologyClusterDisabled} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := NewClient(ctx, initOption(srv.addr()), WithTopology(topology))
		if err != nil {
			cancel()
			t.Fatalf("%v: %v", topology, err)
		}
		v, err := client.Do(ctx, client.B().Get().Key("k").Build()).ToString()
		mode := client.Mode()
		client.Close()
		cancel()
		if err != nil || v != "ok" || mode != valkey.ClientModeStandalone {
			t.Fatalf("%v: GET = %q, %v (mode %v); want ok from a single-node client", topology, v, err, mode)
		}
	}
}

// With Standalone.ReplicaAddress, NewClient connects to the primary and the reader
// endpoint, and the default routing sends reads to the reader and writes to the primary.
func TestNewClient_ReaderEndpointRouting(t *testing.T) {
	node := func(name string, writes *atomic.Int32) func(int64, []string) (string, bool) {
		return func(conn int64, args []string) (string, bool) {
			switch strings.ToUpper(args[0]) {
			case "GET":
				return fmt.Sprintf("$%d\r\n%s\r\n", len(name), name), false
			case "SET":
				writes.Add(1)
			}
			return standaloneReply(conn, args)
		}
	}
	var primaryWrites, readerWrites atomic.Int32
	primary := newFakeValkey(t, node("primary", &primaryWrites))
	reader := newFakeValkey(t, node("reader", &readerWrites))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewClient(ctx, valkey.ClientOption{
		InitAddress: []string{primary.addr()},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{reader.addr()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if v, err := client.Do(ctx, client.B().Get().Key("k").Build()).ToString(); err != nil || v != "reader" {
		t.Fatalf("GET = %q, %v; want the reader endpoint's reply", v, err)
	}
	if err := client.Do(ctx, client.B().Set().Key("k").Value("v").Build()).Error(); err != nil {
		t.Fatal(err)
	}
	if primaryWrites.Load() != 1 || readerWrites.Load() != 0 {
		t.Fatalf("SET reached the primary %d times and the reader %d times, want the primary once", primaryWrites.Load(), readerWrites.Load())
	}
}

// Only IAM puts the dial gate in front of new connections, since only IAM handshakes can
// fail with the IAM backend errors it reacts to. The gate keeps the caller's DialCtxFn
// underneath.
func TestResolve_DialGateForIAMOnly(t *testing.T) {
	plaintext := WithTLS(TLSOptions{Mode: TLSDisabled})
	cases := []struct {
		name  string
		opts  []Option
		gated bool
	}{
		{"IAM", []Option{WithIAMOptions(staticIAM()), plaintext}, true},
		{"Token Auth", []Option{WithTokenAuth(TokenAuthOptions{Token: "t"}), plaintext}, false},
		{"no auth", nil, false},
	}
	for _, c := range cases {
		dials := 0
		local, remote := net.Pipe()
		option := initOption("10.0.0.2:6379")
		option.DialCtxFn = func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
			dials++
			return local, nil
		}
		opt, err := resolveOption(t, option, noReader(t), c.opts...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		conn, err := opt.DialCtxFn(context.Background(), "10.0.0.2:6379", &net.Dialer{}, nil)
		if err != nil || dials != 1 {
			t.Fatalf("%s: dial = %v, the caller's DialCtxFn ran %d times, want once", c.name, err, dials)
		}
		_, gated := conn.(*gatedConn)
		_ = conn.Close()
		_ = remote.Close()
		if gated != c.gated {
			t.Errorf("%s: gated = %v, want %v", c.name, gated, c.gated)
		}
	}
}
