package valkeygcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// T-TLS-1
func TestBuildTLSConfig_AllDiscoveredChains(t *testing.T) {
	ca1, ca2 := newTestCA(t, "current"), newTestCA(t, "successor")
	cfg, err := buildTLSConfig(TLSOptions{}, TLSPerInstanceCA, []string{string(ca1.pem), string(ca2.pem)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x", cfg.MinVersion)
	}
	for _, ca := range []*testCA{ca1, ca2} {
		_, leaf := ca.leaf(t)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs}); err != nil {
			t.Errorf("certificate from %s not trusted: %v", ca.cert.Subject.CommonName, err)
		}
	}
	if cfg.ServerName != "" {
		t.Errorf("ServerName = %q, want empty (verify each dialed IP)", cfg.ServerName)
	}
}

// T-TLS-2
func TestBuildTLSConfig_InvalidPEM(t *testing.T) {
	if _, err := buildTLSConfig(TLSOptions{CAPEM: []byte("not a certificate")}, TLSCustomCA, nil); err == nil {
		t.Fatal("invalid PEM accepted")
	}
	if _, err := buildTLSConfig(TLSOptions{}, TLSPerInstanceCA, []string{"garbage"}); err == nil {
		t.Fatal("invalid discovered PEM accepted")
	}
	if _, err := buildTLSConfig(TLSOptions{CAFile: filepath.Join(t.TempDir(), "missing.pem")}, TLSCustomCA, nil); err == nil ||
		!strings.Contains(err.Error(), "TLSOptions.CAFile") {
		t.Fatalf("missing CAFile: %v", err)
	}
	if _, err := buildTLSConfig(TLSOptions{}, TLSCustomCA, nil); err == nil || !strings.Contains(err.Error(), "needs CA certificates") {
		t.Fatalf("no CA: %v", err)
	}
}

// T-TLS-4
func TestBuildTLSConfig_BaseNotMutated(t *testing.T) {
	ca := newTestCA(t, "ca")
	base := &tls.Config{MinVersion: tls.VersionTLS10, ServerName: "base"}
	cfg, err := buildTLSConfig(TLSOptions{Base: base, CAPEM: ca.pem, ServerName: "override"}, TLSCustomCA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ServerName != "override" || cfg.RootCAs == nil {
		t.Errorf("cfg = MinVersion %x ServerName %q", cfg.MinVersion, cfg.ServerName)
	}
	if base.MinVersion != tls.VersionTLS10 || base.ServerName != "base" || base.RootCAs != nil {
		t.Error("Base was mutated")
	}

	// A caller-built pool in Base is enough on its own.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	cfg, err = buildTLSConfig(TLSOptions{Base: &tls.Config{RootCAs: pool}}, TLSCustomCA, nil)
	if err != nil || cfg.RootCAs != pool || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("Base.RootCAs: %v", err)
	}
}

// T-TLS-5
func TestBuildTLSConfig_Disabled(t *testing.T) {
	for _, mode := range []TLSMode{TLSDisabled, TLSAuto} {
		if cfg, err := buildTLSConfig(TLSOptions{CAPEM: []byte("ignored")}, mode, nil); cfg != nil || err != nil {
			t.Errorf("%v: %v, %v", mode, cfg, err)
		}
	}
}

// T-TLS-6
func TestBuildTLSConfig_Handshake(t *testing.T) {
	ca, other := newTestCA(t, "server-ca"), newTestCA(t, "other-ca")
	cert, _ := ca.leaf(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the wrong-CA handshake is expected to fail
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String() // 127.0.0.1:port, verified against the IP SAN

	dial := func(caPEM []byte) error {
		cfg, err := buildTLSConfig(TLSOptions{CAPEM: caPEM}, TLSCustomCA, nil)
		if err != nil {
			return err
		}
		// Same dial path as valkey.go: tls.Dialer with ServerName left empty.
		conn, err := (&tls.Dialer{Config: cfg}).Dial("tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	if err := dial(ca.pem); err != nil {
		t.Fatalf("handshake with the right CA failed: %v", err)
	}
	if err := dial(other.pem); err == nil {
		t.Fatal("handshake with the wrong CA succeeded")
	}
}

func TestWithTLS(t *testing.T) {
	ca := newTestCA(t, "ca")
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	var opt valkey.ClientOption
	if err := WithTLS(TLSOptions{CAFile: path})(context.Background(), &opt); err != nil || opt.TLSConfig == nil || opt.TLSConfig.RootCAs == nil {
		t.Fatalf("WithTLS(CAFile): %v", err)
	}
	if err := WithTLS(TLSOptions{})(context.Background(), &valkey.ClientOption{}); err == nil {
		t.Fatal("WithTLS without CA material must fail")
	}
	if err := WithTLS(TLSOptions{Mode: TLSSharedCA})(context.Background(), &valkey.ClientOption{}); err == nil || !strings.Contains(err.Error(), "TLSSharedCA") {
		t.Fatalf("shared CA without PEM: %v", err)
	}
}

// tlsServer accepts TLS connections with cert, counts completed handshakes and closes each
// connection right after: it isn't a RESP server, so the client fails after the handshake.
func tlsServer(t *testing.T, cert tls.Certificate) (string, *atomic.Int32) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var handshakes atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if conn.(*tls.Conn).Handshake() == nil {
				handshakes.Add(1)
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &handshakes
}

// WithTLS reaches valkey-go's dialer through both constructors: a server certificate from
// another CA fails verification before any command is sent, and the right CA completes the
// TLS handshake.
func TestWithTLS_Constructors(t *testing.T) {
	ca, other := newTestCA(t, "server-ca"), newTestCA(t, "other-ca")
	cert, _ := ca.leaf(t)
	for _, tc := range []struct {
		name string
		dial func(ctx context.Context, addr string, opts ...GCPOption) (valkey.Client, error)
	}{
		{"NewClusterClient", func(ctx context.Context, addr string, opts ...GCPOption) (valkey.Client, error) {
			return NewClusterClient(ctx, addr, opts...)
		}},
		{"NewStandaloneClient", func(ctx context.Context, addr string, opts ...GCPOption) (valkey.Client, error) {
			return NewStandaloneClient(ctx, addr, addr, opts...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, handshakes := tlsServer(t, cert)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, err := tc.dial(ctx, addr, WithTLS(TLSOptions{Mode: TLSPerInstanceCA, CAPEM: other.pem}))
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("wrong CA: err = %v, want a certificate verification error", err)
			}
			if n := handshakes.Load(); n != 0 {
				t.Fatalf("wrong CA: %d handshakes completed", n)
			}

			client, err := tc.dial(ctx, addr, WithTLS(TLSOptions{Mode: TLSPerInstanceCA, CAPEM: ca.pem}))
			if err == nil {
				client.Close()
				t.Fatal("connected to a server that closes every connection")
			}
			if handshakes.Load() == 0 {
				t.Fatalf("right CA: no TLS handshake completed (err = %v)", err)
			}
		})
	}
}

// Modes outside the TLSMode constants are rejected instead of being treated as TLS on.
func TestWithTLS_UnknownMode(t *testing.T) {
	ca := newTestCA(t, "ca")
	for _, mode := range []TLSMode{-1, TLSCustomCA + 1} {
		err := WithTLS(TLSOptions{Mode: mode, CAPEM: ca.pem})(context.Background(), &valkey.ClientOption{})
		if err == nil || !strings.Contains(err.Error(), "unknown TLS mode") {
			t.Errorf("%v: err = %v, want unknown TLS mode", mode, err)
		}
	}
}

// Base settings other than RootCAs, MinVersion and ServerName are kept, as documented.
func TestBuildTLSConfig_BaseSettingsKept(t *testing.T) {
	ca := newTestCA(t, "ca")
	cfg, err := buildTLSConfig(TLSOptions{CAPEM: ca.pem, Base: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"x"}}}, TLSCustomCA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify || len(cfg.NextProtos) != 1 || cfg.RootCAs == nil {
		t.Errorf("cfg = InsecureSkipVerify %t NextProtos %q", cfg.InsecureSkipVerify, cfg.NextProtos)
	}
}
