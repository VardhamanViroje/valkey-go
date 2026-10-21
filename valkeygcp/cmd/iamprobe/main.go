// Command iamprobe shows how valkeygcp handles Memorystore's IAM throttling error during the
// connection handshake (U8). It runs a fake RESP server on loopback that answers
// HELLO ... AUTH with "-ERR (ERR_IAM_EXHAUSTED) ...", so it needs no network or credentials.
//
//	A  every handshake is throttled: NewClient retries with backoff until its ctx ends
//	B  the first two handshakes are throttled: NewClient retries, then succeeds
//	C  a live connection drops and the next three re-dials are throttled: each re-dial after
//	   an IAM error waits for the dial gate instead of following the request rate
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

const iamExhausted = "-ERR (ERR_IAM_EXHAUSTED) Memorystore IAM authentication backend quota exceeded.\r\n"

type fakeServer struct {
	ln        net.Listener
	start     time.Time
	throttled func(conn int64) bool // answer this connection's HELLO with iamExhausted
	dropConn1 atomic.Bool           // close connection 1 right after its first GET reply

	mu      sync.Mutex
	accepts []time.Duration // when each connection arrived, relative to start
}

func newServer(throttled func(conn int64) bool) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	s := &fakeServer{ln: ln, start: time.Now(), throttled: throttled}
	go s.serve()
	return s
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }

func (s *fakeServer) conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accepts)
}

// arrivals lists when each connection arrived, to show the gaps between attempts.
func (s *fakeServer) arrivals() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for i, d := range s.accepts {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(d.Round(time.Millisecond).String())
	}
	return b.String()
}

func (s *fakeServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepts = append(s.accepts, time.Since(s.start))
		id := int64(len(s.accepts))
		s.mu.Unlock()
		go s.handle(c, id)
	}
}

func (s *fakeServer) handle(c net.Conn, id int64) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		args, err := readCommand(r)
		if err != nil {
			return // EOF or a broken connection
		}
		cmd := strings.ToUpper(args[0])
		var reply string
		switch cmd {
		case "HELLO":
			if s.throttled(id) {
				reply = iamExhausted
			} else {
				reply = "%3\r\n+server\r\n+valkey\r\n+proto\r\n:3\r\n+version\r\n+8.0.0\r\n"
			}
		case "CLUSTER":
			reply = "-ERR This instance has cluster support disabled\r\n"
		case "PING":
			reply = "+PONG\r\n"
		case "GET":
			reply = "$2\r\nok\r\n"
		default:
			reply = "+OK\r\n"
		}
		if _, err := io.WriteString(c, reply); err != nil {
			return
		}
		if cmd == "GET" && id == 1 && s.dropConn1.CompareAndSwap(true, false) {
			return // simulate a dropped connection: the next command must re-dial
		}
	}
}

func readCommand(r *bufio.Reader) ([]string, error) {
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

// cfg is the explicit path with a static IAM token. The fake server has no TLS, so TLS is
// turned off on purpose (valkeygcp refuses to send credentials in plaintext otherwise).
func cfg(addr string) valkeygcp.Config {
	return valkeygcp.Config{
		PrimaryEndpoint: addr,
		TLS:             valkeygcp.TLSOptions{Mode: valkeygcp.TLSDisabled},
		Auth: valkeygcp.AuthOptions{Mode: valkeygcp.AuthIAM, IAM: valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)}),
		}},
	}
}

func main() {
	// A: every handshake is throttled.
	a := newServer(func(int64) bool { return true })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	start := time.Now()
	_, err := valkeygcp.NewClient(ctx, cfg(a.addr()))
	cancel()
	fmt.Printf("A NewClient (2s ctx): err=%v\n  connections=%d elapsed=%s arrivals=[%s]\n",
		err, a.conns(), time.Since(start).Round(time.Millisecond), a.arrivals())

	// B: the first two handshakes are throttled.
	b := newServer(func(id int64) bool { return id <= 2 })
	start = time.Now()
	client, err := valkeygcp.NewClient(context.Background(), cfg(b.addr()))
	fmt.Printf("B NewClient: err=%v\n  connections=%d elapsed=%s arrivals=[%s]\n",
		err, b.conns(), time.Since(start).Round(time.Millisecond), b.arrivals())
	if err == nil {
		client.Close()
	}

	// C: connection 1 drops after its first GET; re-dials 2-4 are throttled.
	c := newServer(func(id int64) bool { return id >= 2 && id <= 4 })
	c.dropConn1.Store(true)
	var retryCalls atomic.Int64
	cc := cfg(c.addr())
	cc.ClientOption = valkey.ClientOption{
		PipelineMultiplex: -1, // one connection, so each re-dial is visible
		RetryDelay: func(attempts int, _ valkey.Completed, err error) time.Duration {
			retryCalls.Add(1)
			fmt.Printf("  RetryDelay(attempt=%d, err=%v)\n", attempts, err)
			return 20 * time.Millisecond
		},
	}
	client, err = valkeygcp.NewClient(context.Background(), cc)
	if err != nil {
		log.Fatalf("C NewClient: %v", err)
	}
	defer client.Close()
	for i := 1; i <= 6; i++ {
		start := time.Now()
		v, err := client.Do(context.Background(), client.B().Get().Key("k").Build()).ToString()
		fmt.Printf("C GET #%d: val=%q err=%v took=%s (connections so far=%d, RetryDelay calls=%d)\n",
			i, v, err, time.Since(start).Round(time.Millisecond), c.conns(), retryCalls.Load())
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("C arrivals=[%s]\n", c.arrivals())
}
