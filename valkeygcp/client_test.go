package valkeygcp

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
	"golang.org/x/oauth2"
)

// NewClient fits the ClientBuilder of valkeylock and valkeyaside. A compile-time check: the
// function is never called, so it needs neither ADC nor a server.
var _ func(valkey.ClientOption) (valkey.Client, error) = func(o valkey.ClientOption) (valkey.Client, error) {
	return NewClient(context.Background(), o, WithDefaultIAM())
}

// topologyShape is a ClientOption for one topology, with the Options that go with it.
type topologyShape struct {
	name   string
	option valkey.ClientOption
	opts   []Option
}

// topologyShapes are the two ways to name a Memorystore endpoint without WithInstance: a
// cluster-mode discovery endpoint, and a cluster-disabled primary with a reader endpoint.
func topologyShapes(addr string) []topologyShape {
	return []topologyShape{
		{"cluster", initOption(addr), []Option{WithTopology(TopologyCluster)}},
		{"cluster disabled", valkey.ClientOption{
			InitAddress: []string{addr},
			Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{addr}},
		}, nil},
	}
}

func TestResolveClientOption_ClusterWiring(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "cluster-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	gcpOpt := WithIAMOptions(IAMAuthOptions{
		CustomTokenSource: mock,
	})

	opt, err := ResolveClientOption(ctx, initOption("10.0.0.15:6379"), WithTopology(TopologyCluster), gcpOpt, WithTLS(TLSOptions{Mode: TLSDisabled}))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.15:6379" || !opt.ClusterOption.PreferInitAddressRefresh ||
		!opt.ClusterOption.PreferClusterShards || opt.ClusterOption.ShardsRefreshInterval != defaultShardsRefreshInterval {
		t.Errorf("cluster options = %+v / %+v", opt.InitAddress, opt.ClusterOption)
	}
	if opt.DialCtxFn == nil {
		t.Error("IAM must space out re-dials after IAM backend errors: no gated dialer")
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "cluster-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

// Errors from what the options set up (IAM credentials, the first Token Auth read, the CA
// bundle) fail NewClient before it dials.
func TestNewClient_OptionSetupErrors(t *testing.T) {
	srv := newFakeValkey(t, standaloneReply)
	plaintext := WithTLS(TLSOptions{Mode: TLSDisabled})
	cases := []struct {
		name string
		opts []Option
		want string
	}{
		{"IAM credentials", []Option{WithIAMOptions(IAMAuthOptions{CredentialsJSON: []byte(`{ invalid-json`)}), plaintext}, "invalid credentials JSON"},
		{"Token Auth first read", []Option{plaintext, WithTokenAuth(TokenAuthOptions{
			Source: func(context.Context) (string, error) { return "", errors.New("permission denied") },
		})}, "initial token fetch"},
		{"CA bundle", []Option{WithTLS(TLSOptions{CAPEM: []byte("not a certificate")})}, "no valid PEM certificate"},
		{"CA file", []Option{WithTLS(TLSOptions{CAFile: filepath.Join(t.TempDir(), "missing.pem")})}, "CAFile"},
	}
	for _, c := range cases {
		for _, shape := range topologyShapes(srv.addr()) {
			_, err := NewClient(context.Background(), shape.option, append(shape.opts, c.opts...)...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s, %s: got %v, want an error containing %q", c.name, shape.name, err, c.want)
			}
		}
	}
	if n := srv.conns.Load(); n != 0 {
		t.Fatalf("connections = %d, want none: setup errors come before dialing", n)
	}
}

func TestResolveClientOption_StandaloneWiring(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "standalone-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	gcpOpt := WithIAMOptions(IAMAuthOptions{
		CustomTokenSource: mock,
	})

	opt, err := ResolveClientOption(ctx, valkey.ClientOption{
		InitAddress: []string{"10.0.0.2:6379"},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}},
	}, gcpOpt, WithTLS(TLSOptions{Mode: TLSDisabled}))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.2:6379" ||
		len(opt.Standalone.ReplicaAddress) != 1 || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" || opt.SendToReplicas == nil {
		t.Errorf("standalone options = %+v / %+v", opt.InitAddress, opt.Standalone)
	}
	if opt.ClusterOption != (valkey.ClusterOption{}) {
		t.Errorf("cluster defaults set next to a reader endpoint: %+v", opt.ClusterOption)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "standalone-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

func TestResolveClientOption_SendToReplicasLogic(t *testing.T) {
	ctx := context.Background()
	capturedOpt, err := ResolveClientOption(ctx, valkey.ClientOption{
		InitAddress: []string{"127.0.0.1:0"},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"127.0.0.1:0"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if capturedOpt.SendToReplicas == nil {
		t.Fatal("expected SendToReplicas to be configured")
	}

	builder := cmds.NewBuilder(cmds.NoSlot)

	// Read-only command (GET) -> should route to replica
	getCmd := builder.Get().Key("k").Build()
	if !capturedOpt.SendToReplicas(getCmd) {
		t.Errorf("expected GET to route to replica, got false")
	}

	// Write command (SET) -> should NOT route to replica
	setCmd := builder.Set().Key("k").Value("v").Build()
	if capturedOpt.SendToReplicas(setCmd) {
		t.Errorf("expected SET NOT to route to replica, got true")
	}

	// Blocking command (BLPOP) -> should NOT route to replica. BLPOP pops an element, so it
	// isn't read-only either.
	blpopCmd := builder.Blpop().Key("k").Timeout(1).Build()
	if capturedOpt.SendToReplicas(blpopCmd) {
		t.Errorf("expected BLPOP NOT to route to replica, got true")
	}
}

func TestResolveClientOption_MemorystoreRetryDelay(t *testing.T) {
	shapes := append(topologyShapes("127.0.0.1:0"), topologyShape{"topology auto", initOption("127.0.0.1:0"), nil})
	for _, shape := range shapes {
		captured, err := ResolveClientOption(context.Background(), shape.option, shape.opts...)
		if err != nil {
			t.Fatalf("%s: got %v", shape.name, err)
		}
		if captured.RetryDelay == nil || captured.RetryDelay(maxRetryAttempts, valkey.Completed{}, nil) >= 0 {
			t.Errorf("%s: RetryDelay is not memorystoreRetryDelay", shape.name)
		}
	}
}

// NewClient's ctx reaches the setup calls (here the first Token Auth read), and a ctx that
// ends during setup stops NewClient before it dials (valkey.NewClient takes no context).
func TestNewClient_ContextDuringSetup(t *testing.T) {
	type key struct{}
	srv := newFakeValkey(t, standaloneReply)
	for _, shape := range topologyShapes(srv.addr()) {
		var got any
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "caller"))
		opts := append(shape.opts, WithTLS(TLSOptions{Mode: TLSDisabled}), WithTokenAuth(TokenAuthOptions{
			Source: func(ctx context.Context) (string, error) {
				got = ctx.Value(key{})
				cancel() // e.g. the caller's deadline passes during setup
				return "tok", nil
			},
		}))
		_, err := NewClient(ctx, shape.option, opts...)
		cancel()
		if got != "caller" {
			t.Fatalf("%s: setup saw ctx value %v, want NewClient's ctx", shape.name, got)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: got %v, want context.Canceled before dialing", shape.name, err)
		}
	}
	if n := srv.conns.Load(); n != 0 {
		t.Fatalf("connections = %d, want none after ctx ended", n)
	}
}

// Missing Application Default Credentials fail setup with the real error, before any dial.
func TestWithDefaultIAM(t *testing.T) {
	// A credentials file that doesn't exist makes ADC fail at once, without probing the
	// metadata server, so the result is the same on laptops, CI and Google Cloud.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	srv := newFakeValkey(t, standaloneReply)
	opt, err := ResolveClientOption(context.Background(), initOption(srv.addr()), WithDefaultIAM(), WithTLS(TLSOptions{Mode: TLSDisabled}))
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("got %v, want the ADC error", err)
	}
	if opt.AuthCredentialsFn != nil {
		t.Error("AuthCredentialsFn set even though setup failed")
	}
	_, err = NewClient(context.Background(), initOption(srv.addr()), WithTopology(TopologyCluster), WithDefaultIAM(), WithTLS(TLSOptions{Mode: TLSDisabled}))
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("NewClient: got %v, want the ADC error", err)
	}
	if n := srv.conns.Load(); n != 0 {
		t.Fatalf("connections = %d, want none", n)
	}
}
