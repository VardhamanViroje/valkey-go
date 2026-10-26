package valkeygcp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
	"golang.org/x/oauth2"
)

// NewClient fits the ClientBuilder of valkeylock and valkeyaside. A compile-time check: the
// builder is never called.
var _ func(valkey.ClientOption) (valkey.Client, error) = func(o valkey.ClientOption) (valkey.Client, error) {
	return NewClient(context.Background(), o, WithDefaultIAM())
}

// staticTokenIAM returns IAM options whose tokens come from a fixed token source.
func staticTokenIAM(token string) IAMAuthOptions {
	return IAMAuthOptions{CustomTokenSource: &mockTokenSource{defaultTok: &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}}}
}

// With a discovery endpoint alone, the cluster defaults and the connection defaults are
// filled in, no reader routing is set, and the IAM token becomes the AUTH password.
func TestResolveClientOption_ClusterWiring(t *testing.T) {
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}},
		WithIAMOptions(staticTokenIAM("cluster-token")))
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.15:6379" || !opt.ClusterOption.PreferInitAddressRefresh ||
		!opt.ClusterOption.PreferClusterShards || opt.ClusterOption.ShardsRefreshInterval != defaultShardsRefreshInterval {
		t.Errorf("cluster options = %+v / %+v", opt.InitAddress, opt.ClusterOption)
	}
	if opt.Dialer.Timeout != defaultDialTimeout || opt.Dialer.KeepAlive != defaultKeepAlive || opt.ConnWriteTimeout != defaultConnWriteTimeout {
		t.Errorf("connection defaults = %v / %v / %v", opt.Dialer.Timeout, opt.Dialer.KeepAlive, opt.ConnWriteTimeout)
	}
	if len(opt.Standalone.ReplicaAddress) != 0 || opt.SendToReplicas != nil {
		t.Errorf("reader routing set without a reader endpoint: %v", opt.Standalone.ReplicaAddress)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "cluster-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

// With a reader endpoint, reads are routed to it and the cluster defaults are left out.
func TestResolveClientOption_StandaloneWiring(t *testing.T) {
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{
		InitAddress: []string{"10.0.0.2:6379"},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}},
	}, WithIAMOptions(staticTokenIAM("standalone-token")))
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.2:6379" ||
		len(opt.Standalone.ReplicaAddress) != 1 || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" || opt.SendToReplicas == nil {
		t.Errorf("standalone options = %+v / %+v", opt.InitAddress, opt.Standalone)
	}
	if opt.ClusterOption != (valkey.ClusterOption{}) {
		t.Errorf("cluster defaults set with a reader endpoint: %+v", opt.ClusterOption)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "standalone-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

// Every InitAddress and Standalone.ReplicaAddress value is kept as given.
func TestResolveClientOption_AddressesKept(t *testing.T) {
	seeds := []string{"10.0.0.15:6379", "10.0.0.16:6379", "10.0.0.17:6379"}
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{InitAddress: seeds})
	if err != nil || !slices.Equal(opt.InitAddress, seeds) {
		t.Fatalf("InitAddress = %v, %v; want %v", opt.InitAddress, err, seeds)
	}
	replicas := []string{"10.0.0.3:6379", "10.0.0.4:6379"}
	opt, err = ResolveClientOption(context.Background(), valkey.ClientOption{
		InitAddress: seeds[:1],
		Standalone:  valkey.StandaloneOption{ReplicaAddress: replicas},
	})
	if err != nil || !slices.Equal(opt.Standalone.ReplicaAddress, replicas) {
		t.Fatalf("ReplicaAddress = %v, %v; want %v", opt.Standalone.ReplicaAddress, err, replicas)
	}
}

// A primary endpoint without a reader endpoint (an instance without replicas) needs no
// Standalone.ReplicaAddress, and no reader routing is set up.
func TestResolveClientOption_NoReader(t *testing.T) {
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{InitAddress: []string{"10.0.0.2:6379"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.Standalone.ReplicaAddress) != 0 || opt.SendToReplicas != nil {
		t.Fatalf("reader routing = %v / %v, want none", opt.Standalone.ReplicaAddress, opt.SendToReplicas != nil)
	}
}

// Without InitAddress there is nothing to connect to, so ResolveClientOption fails.
func TestResolveClientOption_NoEndpoint(t *testing.T) {
	if _, err := ResolveClientOption(context.Background(), valkey.ClientOption{}, WithDefaultIAM()); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("got %v, want %v", err, errNoEndpoint)
	}
}

// Values set on the ClientOption beat the Memorystore defaults.
func TestResolveClientOption_CallerValuesWin(t *testing.T) {
	retry := func(int, valkey.Completed, error) time.Duration { return time.Second }
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{
		InitAddress:      []string{"10.0.0.15:6379"},
		Dialer:           net.Dialer{Timeout: 7 * time.Second, KeepAlive: 9 * time.Second},
		ConnWriteTimeout: 11 * time.Second,
		ClusterOption:    valkey.ClusterOption{ShardsRefreshInterval: time.Minute},
		RetryDelay:       retry,
	})
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case opt.Dialer.Timeout != 7*time.Second || opt.Dialer.KeepAlive != 9*time.Second:
		t.Errorf("Dialer = %v / %v", opt.Dialer.Timeout, opt.Dialer.KeepAlive)
	case opt.ConnWriteTimeout != 11*time.Second:
		t.Errorf("ConnWriteTimeout = %v", opt.ConnWriteTimeout)
	case opt.ClusterOption.ShardsRefreshInterval != time.Minute:
		t.Errorf("ShardsRefreshInterval = %v", opt.ClusterOption.ShardsRefreshInterval)
	case opt.RetryDelay(0, valkey.Completed{}, nil) != time.Second:
		t.Error("RetryDelay replaced")
	}

	everything := func(valkey.Completed) bool { return true }
	opt, err = ResolveClientOption(context.Background(), valkey.ClientOption{
		InitAddress:    []string{"10.0.0.2:6379"},
		Standalone:     valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}},
		SendToReplicas: everything,
	})
	if err != nil || !opt.SendToReplicas(cmds.NewBuilder(cmds.NoSlot).Set().Key("k").Value("v").Build()) {
		t.Fatalf("SendToReplicas replaced: %v", err)
	}
}

// Credentials set on the ClientOption are used as is; next to an IAM option they are an error.
func TestResolveClientOption_CallerCredentials(t *testing.T) {
	ownFn := func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		return valkey.AuthCredentials{}, nil
	}
	for field, option := range map[string]valkey.ClientOption{
		"Password":          {InitAddress: []string{"10.0.0.15:6379"}, Password: "secret"},
		"AuthCredentialsFn": {InitAddress: []string{"10.0.0.15:6379"}, AuthCredentialsFn: ownFn},
	} {
		_, err := ResolveClientOption(context.Background(), option, WithIAMOptions(staticTokenIAM("t")))
		if err == nil || !strings.Contains(err.Error(), "ClientOption."+field+" conflicts with WithIAMOptions") {
			t.Errorf("%s with WithIAMOptions: got %v", field, err)
		}
		opt, err := ResolveClientOption(context.Background(), option)
		if err != nil || opt.Password != option.Password || (opt.AuthCredentialsFn != nil) != (option.AuthCredentialsFn != nil) {
			t.Errorf("%s alone: not kept as is (%v)", field, err)
		}
	}
}

// Later options override earlier ones; a nil option is skipped.
func TestResolveClientOption_LastIAMOptionWins(t *testing.T) {
	opt, err := ResolveClientOption(context.Background(), valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}},
		WithDefaultIAM(), nil, WithIAMOptions(staticTokenIAM("last")))
	if err != nil {
		t.Fatal(err) // WithDefaultIAM would need ADC
	}
	if creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{}); err != nil || creds.Password != "last" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

// The default routing sends read-only commands to the reader endpoint, and writes and
// blocking commands to the primary.
func TestResolveClientOption_SendToReplicasLogic(t *testing.T) {
	capturedOpt, err := ResolveClientOption(context.Background(), valkey.ClientOption{
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

// Both cluster and standalone options get memorystoreRetryDelay as RetryDelay.
func TestResolveClientOption_MemorystoreRetryDelay(t *testing.T) {
	for name, option := range map[string]valkey.ClientOption{
		"cluster":    {InitAddress: []string{"127.0.0.1:0"}},
		"standalone": {InitAddress: []string{"127.0.0.1:0"}, Standalone: valkey.StandaloneOption{ReplicaAddress: []string{"127.0.0.1:0"}}},
	} {
		opt, err := ResolveClientOption(context.Background(), option)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if opt.RetryDelay == nil || opt.RetryDelay(maxRetryAttempts, valkey.Completed{}, nil) >= 0 {
			t.Errorf("%s: RetryDelay is not memorystoreRetryDelay", name)
		}
	}
}

// A ctx that has ended during setup stops NewClient before it dials
// (valkey.NewClient takes no context).
func TestNewClient_ContextEndedBeforeDial(t *testing.T) {
	var dials atomic.Int32
	dial := func(context.Context, string, *net.Dialer, *tls.Config) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dialed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClient(ctx, valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}, DialCtxFn: dial},
		WithIAMOptions(staticTokenIAM("t")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled before dialing", err)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("dialed %d times with an ended ctx", n)
	}
}

// Missing Application Default Credentials (ADC) fail setup with the real error, before any
// dial.
func TestWithDefaultIAM(t *testing.T) {
	// A credentials file that doesn't exist makes ADC fail at once, without probing the
	// metadata server, so the result is the same on laptops, CI and Google Cloud.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	option := valkey.ClientOption{InitAddress: []string{"127.0.0.1:0"}}
	opt, err := ResolveClientOption(context.Background(), option, WithDefaultIAM())
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("got %v, want the ADC error", err)
	}
	if opt.AuthCredentialsFn != nil {
		t.Error("AuthCredentialsFn set even though setup failed")
	}
	_, err = NewClient(context.Background(), option, WithDefaultIAM())
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("NewClient: got %v, want the ADC error", err)
	}
}
