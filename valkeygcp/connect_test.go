package valkeygcp

import (
	"bufio"
	"context"
	"crypto/tls"
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

	"github.com/valkey-io/valkey-go"
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

// iamOptions are Options with a static IAM token. extra comes last, so it can override them.
func iamOptions(extra ...Option) []Option {
	return append([]Option{WithIAMOptions(staticIAM())}, extra...)
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

// Only IAM puts the dial gate in front of new connections, since only IAM handshakes can
// fail with the IAM backend errors it reacts to. The gate keeps the caller's DialCtxFn
// underneath.
func TestResolve_DialGateForIAMOnly(t *testing.T) {
	cases := []struct {
		name  string
		opts  []Option
		gated bool
	}{
		{"IAM", []Option{WithIAMOptions(staticIAM())}, true},
		{"no auth option", nil, false},
	}
	for _, c := range cases {
		dials := 0
		local, remote := net.Pipe()
		option := initOption("10.0.0.2:6379")
		option.DialCtxFn = func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
			dials++
			return local, nil
		}
		opt, err := ResolveClientOption(context.Background(), option, c.opts...)
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

// The hint names the AUTH user: here the IAM username set in IAMAuthOptions.Username.
func TestNewClient_ClientTrackingHintNamesIAMUser(t *testing.T) {
	srv := newFakeValkey(t, func(conn int64, args []string) (string, bool) {
		if len(args) > 1 && strings.EqualFold(args[0], "CLIENT") && strings.EqualFold(args[1], "TRACKING") {
			return "-NOPERM User app has no permissions to run the 'client|tracking' command\r\n", false
		}
		return standaloneReply(conn, args)
	})
	opts := staticIAM()
	opts.Username = "app@p.iam.gserviceaccount.com"
	_, err := NewClient(context.Background(), initOption(srv.addr()), WithIAMOptions(opts))
	if err == nil || !strings.Contains(err.Error(), `ACL rule for user "app@p.iam.gserviceaccount.com" must allow CLIENT TRACKING`) {
		t.Fatalf("got %v, want the hint naming the IAM username", err)
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
