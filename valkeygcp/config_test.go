package valkeygcp

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
)

// noReader fails the test if resolution touches the control plane.
func noReader(t *testing.T) func(context.Context) (instanceReader, error) {
	return func(context.Context) (instanceReader, error) {
		t.Fatal("explicit config must not call the Memorystore API")
		return nil, nil
	}
}

func resolveOption(t *testing.T, cfg Config, newReader func(context.Context) (instanceReader, error)) (valkey.ClientOption, error) {
	t.Helper()
	r, err := resolve(context.Background(), cfg, newReader)
	if err != nil {
		return valkey.ClientOption{}, err
	}
	return r.clientOption(context.Background())
}

// T-CFG-1
func TestResolve_NoEndpoint(t *testing.T) {
	_, err := resolveOption(t, Config{}, noReader(t))
	if !errors.Is(err, errNoEndpoint) {
		t.Fatalf("got %v, want %v", err, errNoEndpoint)
	}
	if _, err := resolveOption(t, Config{ReaderEndpoint: "10.0.0.3:6379"}, noReader(t)); err == nil {
		t.Fatal("ReaderEndpoint alone must be rejected")
	}
}

// T-CFG-2
func TestResolve_ExplicitClusterIAM(t *testing.T) {
	opt, err := resolveOption(t, Config{
		DiscoveryEndpoint: "10.0.0.15:6379",
		Auth:              AuthOptions{Mode: AuthIAM, IAM: staticIAM()},
	}, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.15:6379" {
		t.Errorf("InitAddress = %v", opt.InitAddress)
	}
	if opt.AuthCredentialsFn == nil {
		t.Fatal("AuthCredentialsFn not set")
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "iam-token" {
		t.Errorf("creds = %+v, %v", creds, err)
	}
	if opt.TLSConfig != nil {
		t.Error("TLSConfig must be nil without TLS options")
	}
	want := valkey.ClusterOption{PreferInitAddressRefresh: true, ShardsRefreshInterval: 10 * time.Second, PreferClusterShards: true}
	if opt.ClusterOption != want {
		t.Errorf("ClusterOption = %+v, want %+v", opt.ClusterOption, want)
	}
	if opt.Dialer.Timeout != 2*time.Second || opt.Dialer.KeepAlive != time.Second || opt.ConnWriteTimeout != 3*time.Second {
		t.Errorf("connection defaults = %v/%v/%v", opt.Dialer.Timeout, opt.Dialer.KeepAlive, opt.ConnWriteTimeout)
	}
	if opt.RetryDelay == nil || opt.RetryDelay(maxRetryAttempts, valkey.Completed{}, nil) >= 0 {
		t.Error("RetryDelay must be memorystoreRetryDelay")
	}
	if len(opt.Standalone.ReplicaAddress) != 0 || opt.SendToReplicas != nil {
		t.Error("cluster mode must not configure the reader endpoint")
	}
}

// T-CFG-3
func TestResolve_ExplicitClusterDisabled(t *testing.T) {
	opt, err := resolveOption(t, Config{PrimaryEndpoint: "10.0.0.2:6379", ReaderEndpoint: "10.0.0.3:6379"}, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.2:6379" {
		t.Errorf("InitAddress = %v", opt.InitAddress)
	}
	if len(opt.Standalone.ReplicaAddress) != 1 || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" {
		t.Errorf("ReplicaAddress = %v", opt.Standalone.ReplicaAddress)
	}
	if opt.SendToReplicas == nil {
		t.Fatal("SendToReplicas not set")
	}
	b := cmds.NewBuilder(cmds.NoSlot)
	if !opt.SendToReplicas(b.Get().Key("k").Build()) {
		t.Error("GET should go to the reader")
	}
	if opt.SendToReplicas(b.Set().Key("k").Value("v").Build()) {
		t.Error("SET must go to the primary")
	}
	if opt.SendToReplicas(b.Blpop().Key("k").Timeout(1).Build()) {
		t.Error("blocking reads must go to the primary (C5)")
	}
	if opt.AuthCredentialsFn != nil || opt.TLSConfig != nil {
		t.Error("no auth and no TLS expected")
	}
	if opt.ClusterOption != (valkey.ClusterOption{}) {
		t.Errorf("cluster defaults applied to a cluster-disabled config: %+v", opt.ClusterOption)
	}

	// Without a reader, no read routing is configured.
	opt, err = resolveOption(t, Config{PrimaryEndpoint: "10.0.0.2:6379"}, noReader(t))
	if err != nil || len(opt.Standalone.ReplicaAddress) != 0 || opt.SendToReplicas != nil {
		t.Errorf("primary only: %+v, %v", opt.Standalone, err)
	}
}

// T-CFG-4
func TestResolve_CallerOptionsPreserved(t *testing.T) {
	retry := func(int, valkey.Completed, error) time.Duration { return 42 }
	caller := &tls.Config{ServerName: "caller"}
	opt, err := resolveOption(t, Config{
		DiscoveryEndpoint: "10.0.0.15:6379",
		ClientOption: valkey.ClientOption{
			InitAddress:      []string{"proxy:6379"},
			RetryDelay:       retry,
			ConnWriteTimeout: 9 * time.Second,
			TLSConfig:        caller,
			ClusterOption:    valkey.ClusterOption{ShardsRefreshInterval: time.Minute},
		},
		TLS: TLSOptions{Mode: TLSCustomCA},
	}, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	opt2 := Config{ClientOption: valkey.ClientOption{}}
	opt2.ClientOption.Dialer.Timeout = 7 * time.Second
	opt2.DiscoveryEndpoint = "10.0.0.15:6379"
	got2, err := resolveOption(t, opt2, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	if got2.Dialer.Timeout != 7*time.Second || got2.Dialer.KeepAlive != time.Second {
		t.Errorf("Dialer = %v/%v", got2.Dialer.Timeout, got2.Dialer.KeepAlive)
	}
	if opt.RetryDelay(0, valkey.Completed{}, nil) != 42 {
		t.Error("RetryDelay was overwritten")
	}
	if opt.ConnWriteTimeout != 9*time.Second || opt.InitAddress[0] != "proxy:6379" || opt.TLSConfig != caller {
		t.Errorf("caller values overwritten: %v %v %v", opt.ConnWriteTimeout, opt.InitAddress, opt.TLSConfig)
	}
	if opt.ClusterOption.ShardsRefreshInterval != time.Minute || !opt.ClusterOption.PreferInitAddressRefresh {
		t.Errorf("ClusterOption = %+v", opt.ClusterOption)
	}
}

// T-CFG-5
func TestResolve_CallerCredentialsConflict(t *testing.T) {
	fn := func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		return valkey.AuthCredentials{}, nil
	}
	_, err := resolveOption(t, Config{
		DiscoveryEndpoint: "10.0.0.15:6379",
		Auth:              AuthOptions{Mode: AuthIAM, IAM: staticIAM()},
		ClientOption:      valkey.ClientOption{AuthCredentialsFn: fn},
	}, noReader(t))
	if err == nil || !strings.Contains(err.Error(), "ClientOption.AuthCredentialsFn conflicts with Auth.Mode") {
		t.Fatalf("got %v", err)
	}
	_, err = resolveOption(t, Config{
		DiscoveryEndpoint: "10.0.0.15:6379",
		Auth:              AuthOptions{Mode: AuthToken, Token: TokenAuthOptions{Token: "t"}},
		ClientOption:      valkey.ClientOption{Password: "static"},
	}, noReader(t))
	if err == nil || !strings.Contains(err.Error(), "ClientOption.Password conflicts with Auth.Mode") {
		t.Fatalf("got %v", err)
	}

	// With AuthAuto the caller's credentials are used as is.
	opt, err := resolveOption(t, Config{
		DiscoveryEndpoint: "10.0.0.15:6379",
		Auth:              AuthOptions{IAM: staticIAM()},
		ClientOption:      valkey.ClientOption{Password: "static"},
	}, noReader(t))
	if err != nil || opt.AuthCredentialsFn != nil || opt.Password != "static" {
		t.Fatalf("caller credentials not kept: fn=%v pw=%q err=%v", opt.AuthCredentialsFn != nil, opt.Password, err)
	}
}

func TestResolve_AuthAutoInference(t *testing.T) {
	base := Config{DiscoveryEndpoint: "10.0.0.15:6379"}
	cases := []struct {
		name string
		auth AuthOptions
		want AuthMode
		err  string
	}{
		{"nothing", AuthOptions{}, AuthDisabled, ""},
		{"token", AuthOptions{Token: TokenAuthOptions{Token: "t"}}, AuthToken, ""},
		{"iam identity", AuthOptions{IAM: staticIAM()}, AuthIAM, ""},
		{"iam username", AuthOptions{IAM: IAMAuthOptions{Username: "u"}}, AuthIAM, ""},
		{"iam tuning only", AuthOptions{IAM: IAMAuthOptions{RefreshBuffer: time.Minute}}, AuthDisabled, ""},
		{"both", AuthOptions{IAM: staticIAM(), Token: TokenAuthOptions{Token: "t"}}, 0, "set Auth.Mode"},
		{"token mode without source", AuthOptions{Mode: AuthToken}, 0, "Auth.Token.SecretVersion"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			cfg.Auth = c.auth
			r, err := resolve(context.Background(), cfg, noReader(t))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("got %v, want error containing %q", err, c.err)
				}
				return
			}
			if err != nil || r.auth != c.want {
				t.Fatalf("got %v, %v; want %v", r, err, c.want)
			}
		})
	}
}

func TestResolve_TLSAndTopologyInference(t *testing.T) {
	ca := newTestCA(t, "explicit")
	r, err := resolve(context.Background(), Config{PrimaryEndpoint: "10.0.0.2:6379", TLS: TLSOptions{CAPEM: ca.pem}}, noReader(t))
	if err != nil || r.tls != TLSCustomCA || r.topology != TopologyClusterDisabled {
		t.Fatalf("got %+v, %v", r, err)
	}
	if _, err := resolve(context.Background(), Config{PrimaryEndpoint: "p:1", TLS: TLSOptions{ServerName: "x"}}, noReader(t)); err == nil {
		t.Fatal("TLS options without CA material must fail")
	}
	if _, err := resolve(context.Background(), Config{PrimaryEndpoint: "p:1", TLS: TLSOptions{Mode: TLSPerInstanceCA}}, noReader(t)); err == nil ||
		!strings.Contains(err.Error(), "Config.Instance") {
		t.Fatalf("per-instance CA without Instance: %v", err)
	}
	if _, err := resolve(context.Background(), Config{DiscoveryEndpoint: "d:1", PrimaryEndpoint: "p:1"}, noReader(t)); err == nil {
		t.Fatal("both endpoints without Topology must fail")
	}
	r, err = resolve(context.Background(), Config{DiscoveryEndpoint: "d:1", PrimaryEndpoint: "p:1", Topology: TopologyCluster}, noReader(t))
	if err == nil {
		t.Fatalf("PrimaryEndpoint with TopologyCluster must fail, got %+v", r)
	}
	if _, err := resolve(context.Background(), Config{DiscoveryEndpoint: "d:1", Topology: TopologyClusterDisabled}, noReader(t)); err == nil {
		t.Fatal("DiscoveryEndpoint with TopologyClusterDisabled must fail")
	}
	r, err = resolve(context.Background(), Config{ClientOption: valkey.ClientOption{InitAddress: []string{"a:1"}}}, noReader(t))
	if err != nil || r.topology != TopologyAuto {
		t.Fatalf("ClientOption.InitAddress alone: %+v, %v", r, err)
	}
	for _, cfg := range []Config{
		{DiscoveryEndpoint: "d:1", Auth: AuthOptions{Mode: AuthMode(9)}},
		{DiscoveryEndpoint: "d:1", TLS: TLSOptions{Mode: TLSMode(9)}},
		{DiscoveryEndpoint: "d:1", Topology: Topology(9)},
	} {
		if _, err := resolve(context.Background(), cfg, noReader(t)); err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Errorf("unknown enum accepted: %v", err)
		}
	}
}

func TestResolve_ExplicitTLSAndToken(t *testing.T) {
	ca := newTestCA(t, "explicit")
	var sourceCalls int
	opt, err := resolveOption(t, Config{
		PrimaryEndpoint: "10.0.0.2:6379",
		Auth: AuthOptions{Token: TokenAuthOptions{Username: "app", Source: func(context.Context) (string, error) {
			sourceCalls++
			return "tok", nil
		}}},
		TLS: TLSOptions{CAPEM: ca.pem},
	}, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	if opt.TLSConfig == nil || opt.TLSConfig.RootCAs == nil || opt.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLSConfig = %+v", opt.TLSConfig)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != "app" || creds.Password != "tok" || sourceCalls != 1 {
		t.Fatalf("creds = %+v, %v (source calls %d)", creds, err, sourceCalls)
	}
}

func TestResolveClientOption_Public(t *testing.T) {
	opt, err := ResolveClientOption(context.Background(), Config{DiscoveryEndpoint: "10.0.0.15:6379"})
	if err != nil || opt.InitAddress[0] != "10.0.0.15:6379" {
		t.Fatalf("got %v, %v", opt.InitAddress, err)
	}
	if _, err := ResolveClientOption(context.Background(), Config{}); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewClient(context.Background(), Config{}); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("NewClient: got %v", err)
	}
}

func TestModeStrings(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{AuthIAM.String(), "AuthIAM"}, {AuthMode(7).String(), "AuthMode(7)"},
		{TLSSharedCA.String(), "TLSSharedCA"}, {TLSMode(7).String(), "TLSMode(7)"},
		{TopologyClusterDisabled.String(), "TopologyClusterDisabled"}, {Topology(7).String(), "Topology(7)"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// AuthOptions.OnCredentialError reaches the Token Auth provider like it reaches IAM.
func TestResolve_TokenAuthGetsOnCredentialError(t *testing.T) {
	fail, absorbed := false, 0
	opt, err := resolveOption(t, Config{
		PrimaryEndpoint: "10.0.0.2:6379",
		Auth: AuthOptions{
			Token: TokenAuthOptions{ReloadInterval: 40 * time.Millisecond, Source: func(context.Context) (string, error) {
				if fail {
					return "", errors.New("secret manager unavailable")
				}
				return "tok", nil
			}},
			OnCredentialError: func(error) { absorbed++ },
		},
	}, noReader(t))
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	time.Sleep(30 * time.Millisecond) // past the cache window (ReloadInterval/2)
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "tok" || absorbed != 1 {
		t.Fatalf("creds = %+v, %v; OnCredentialError calls = %d, want the last token and 1 call", creds, err, absorbed)
	}
}

// NewClient stops before dialing when ctx ended during setup (valkey.NewClient takes no context).
func TestNewClient_ContextEndedBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewClient(ctx, Config{PrimaryEndpoint: "127.0.0.1:0"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}
