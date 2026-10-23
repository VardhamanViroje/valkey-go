package valkeygcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
	"golang.org/x/oauth2"
)

// noReader fails the test if resolution touches the control plane.
func noReader(t *testing.T) readerFactory {
	return func(context.Context, googleAPI) (instanceReader, error) {
		t.Fatal("this resolution must not call the Memorystore API")
		return nil, nil
	}
}

// initOption is a ClientOption whose InitAddress names the endpoints, as callers do
// without WithInstance.
func initOption(addrs ...string) valkey.ClientOption {
	return valkey.ClientOption{InitAddress: addrs}
}

// resolveWith runs resolve with opts, using newReader in place of the Memorystore API.
func resolveWith(option valkey.ClientOption, newReader readerFactory, opts ...Option) (*resolved, error) {
	return resolve(context.Background(), option, newConfig(opts), newReader)
}

// resolveOption returns the ClientOption NewClient would connect with, like
// ResolveClientOption, using newReader in place of the Memorystore API.
func resolveOption(t *testing.T, option valkey.ClientOption, newReader readerFactory, opts ...Option) (valkey.ClientOption, error) {
	t.Helper()
	r, err := resolveWith(option, newReader, opts...)
	if err != nil {
		return valkey.ClientOption{}, err
	}
	return r.clientOption(context.Background())
}

// T-CFG-1
func TestResolve_NoEndpoint(t *testing.T) {
	_, err := resolveOption(t, valkey.ClientOption{}, noReader(t))
	if !errors.Is(err, errNoEndpoint) {
		t.Fatalf("got %v, want %v", err, errNoEndpoint)
	}
	replicaOnly := valkey.ClientOption{Standalone: valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}}}
	if _, err := resolveOption(t, replicaOnly, noReader(t)); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("Standalone.ReplicaAddress alone must be rejected: got %v", err)
	}
	for _, topology := range []Topology{TopologyCluster, TopologyClusterDisabled} {
		if _, err := resolveOption(t, valkey.ClientOption{}, noReader(t), WithTopology(topology)); !errors.Is(err, errNoEndpoint) {
			t.Errorf("%v without InitAddress: got %v, want %v", topology, err, errNoEndpoint)
		}
	}
}

// T-CFG-2
func TestResolve_ExplicitClusterIAM(t *testing.T) {
	opt, err := resolveOption(t, initOption("10.0.0.15:6379"), noReader(t),
		WithTopology(TopologyCluster),
		WithIAMOptions(staticIAM()),
		WithTLS(TLSOptions{Mode: TLSDisabled}), // explicit opt-in to plaintext (U10)
	)
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
	withReader := valkey.ClientOption{
		InitAddress: []string{"10.0.0.2:6379"},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}},
	}
	// A reader endpoint is only for cluster mode disabled, whether WithTopology says so or not.
	for _, topology := range []Topology{TopologyAuto, TopologyClusterDisabled} {
		opt, err := resolveOption(t, withReader, noReader(t), WithTopology(topology))
		if err != nil {
			t.Fatal(err)
		}
		if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.2:6379" {
			t.Errorf("%v: InitAddress = %v", topology, opt.InitAddress)
		}
		if len(opt.Standalone.ReplicaAddress) != 1 || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" {
			t.Errorf("%v: ReplicaAddress = %v", topology, opt.Standalone.ReplicaAddress)
		}
		if opt.SendToReplicas == nil {
			t.Fatalf("%v: SendToReplicas not set", topology)
		}
		b := cmds.NewBuilder(cmds.NoSlot)
		if !opt.SendToReplicas(b.Get().Key("k").Build()) {
			t.Errorf("%v: GET should go to the reader", topology)
		}
		if opt.SendToReplicas(b.Set().Key("k").Value("v").Build()) {
			t.Errorf("%v: SET must go to the primary", topology)
		}
		if opt.SendToReplicas(b.Blpop().Key("k").Timeout(1).Build()) {
			t.Errorf("%v: blocking reads must go to the primary (C5)", topology)
		}
		if opt.AuthCredentialsFn != nil || opt.TLSConfig != nil {
			t.Errorf("%v: no auth and no TLS expected", topology)
		}
		if opt.ClusterOption != (valkey.ClusterOption{}) {
			t.Errorf("%v: cluster defaults applied to a cluster-disabled config: %+v", topology, opt.ClusterOption)
		}
	}

	// Without a reader, no read routing is configured.
	opt, err := resolveOption(t, initOption("10.0.0.2:6379"), noReader(t), WithTopology(TopologyClusterDisabled))
	if err != nil || len(opt.Standalone.ReplicaAddress) != 0 || opt.SendToReplicas != nil {
		t.Errorf("primary only: %+v, %v", opt.Standalone, err)
	}
}

// T-CFG-4: values the caller set on the ClientOption beat the Memorystore defaults.
func TestResolve_CallerOptionsPreserved(t *testing.T) {
	retry := func(int, valkey.Completed, error) time.Duration { return 42 }
	everything := func(valkey.Completed) bool { return true } // writes too, unlike sendReadsToReplicas
	caller := &tls.Config{ServerName: "caller"}
	ca := newTestCA(t, "unused")
	set := cmds.NewBuilder(cmds.NoSlot).Set().Key("k").Value("v").Build()
	cases := []struct {
		name   string
		set    func(*valkey.ClientOption)
		opts   []Option
		intact func(valkey.ClientOption) bool
	}{
		{"Dialer.Timeout", func(o *valkey.ClientOption) { o.Dialer.Timeout = 7 * time.Second }, nil,
			func(o valkey.ClientOption) bool {
				return o.Dialer.Timeout == 7*time.Second && o.Dialer.KeepAlive == defaultKeepAlive
			}},
		{"Dialer.KeepAlive", func(o *valkey.ClientOption) { o.Dialer.KeepAlive = 5 * time.Second }, nil,
			func(o valkey.ClientOption) bool {
				return o.Dialer.KeepAlive == 5*time.Second && o.Dialer.Timeout == defaultDialTimeout
			}},
		{"ConnWriteTimeout", func(o *valkey.ClientOption) { o.ConnWriteTimeout = 9 * time.Second }, nil,
			func(o valkey.ClientOption) bool { return o.ConnWriteTimeout == 9*time.Second }},
		{"ClusterOption.ShardsRefreshInterval", func(o *valkey.ClientOption) { o.ClusterOption.ShardsRefreshInterval = time.Minute },
			[]Option{WithTopology(TopologyCluster)},
			func(o valkey.ClientOption) bool {
				return o.ClusterOption.ShardsRefreshInterval == time.Minute && o.ClusterOption.PreferInitAddressRefresh && o.ClusterOption.PreferClusterShards
			}},
		{"RetryDelay", func(o *valkey.ClientOption) { o.RetryDelay = retry }, nil,
			func(o valkey.ClientOption) bool { return o.RetryDelay(0, valkey.Completed{}, nil) == 42 }},
		{"SendToReplicas with a reader endpoint", func(o *valkey.ClientOption) {
			o.Standalone.ReplicaAddress = []string{"10.0.0.3:6379"}
			o.SendToReplicas = everything
		}, nil, func(o valkey.ClientOption) bool { return o.SendToReplicas != nil && o.SendToReplicas(set) }},
		{"SendToReplicas for cluster replicas", func(o *valkey.ClientOption) { o.SendToReplicas = everything }, nil,
			func(o valkey.ClientOption) bool { return o.SendToReplicas != nil && o.SendToReplicas(set) }},
		{"TLSConfig", func(o *valkey.ClientOption) { o.TLSConfig = caller }, []Option{WithTLS(TLSOptions{Mode: TLSCustomCA})},
			func(o valkey.ClientOption) bool { return o.TLSConfig == caller }},
		{"TLSConfig over CA material", func(o *valkey.ClientOption) { o.TLSConfig = caller }, []Option{WithTLS(TLSOptions{CAPEM: ca.pem})},
			func(o valkey.ClientOption) bool { return o.TLSConfig == caller }},
	}
	for _, c := range cases {
		option := initOption("10.0.0.15:6379")
		c.set(&option)
		opt, err := resolveOption(t, option, noReader(t), c.opts...)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !c.intact(opt) {
			t.Errorf("%s: the caller's value was overwritten", c.name)
		}
	}
}

// T-CFG-5: credentials set on the ClientOption are used as is, so an auth option next to
// them is a contradiction.
func TestResolve_CallerCredentialsConflict(t *testing.T) {
	fn := func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		return valkey.AuthCredentials{Username: "caller", Password: "caller-secret"}, nil
	}
	withFn := initOption("10.0.0.15:6379")
	withFn.AuthCredentialsFn = fn
	withPassword := initOption("10.0.0.15:6379")
	withPassword.Password = "static"
	token := WithTokenAuth(TokenAuthOptions{Token: "t"})
	conflicts := []struct {
		name   string
		option valkey.ClientOption
		opts   []Option
		want   string
	}{
		{"AuthCredentialsFn and WithIAMOptions", withFn, []Option{WithIAMOptions(staticIAM())}, "ClientOption.AuthCredentialsFn conflicts with WithIAMOptions"},
		{"AuthCredentialsFn and WithDefaultIAM", withFn, []Option{WithDefaultIAM()}, "ClientOption.AuthCredentialsFn conflicts with WithIAMOptions"},
		{"AuthCredentialsFn and WithTokenAuth", withFn, []Option{token}, "ClientOption.AuthCredentialsFn conflicts with WithTokenAuth"},
		{"Password and WithIAMOptions", withPassword, []Option{WithIAMOptions(staticIAM())}, "ClientOption.Password conflicts with WithIAMOptions"},
		{"Password and WithTokenAuth", withPassword, []Option{token}, "ClientOption.Password conflicts with WithTokenAuth"},
		{"Password and both", withPassword, []Option{WithIAMOptions(staticIAM()), token}, "ClientOption.Password conflicts with WithIAMOptions and WithTokenAuth"},
		// Caught before the instance is read.
		{"Password, both and an instance", withPassword, []Option{WithInstance(testInstance), WithIAMOptions(staticIAM()), token},
			"ClientOption.Password conflicts with WithIAMOptions and WithTokenAuth"},
	}
	for _, c := range conflicts {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolveOption(t, c.option, noReader(t), c.opts...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}

	// Without an auth option the caller's credentials are used as is, also when the instance
	// requires IAM or Token Auth.
	kept := []struct {
		name   string
		option valkey.ClientOption
		reader readerFactory
		opts   []Option
	}{
		{"Password", withPassword, noReader(t), nil},
		{"AuthCredentialsFn", withFn, noReader(t), nil},
		{"Password, IAM_AUTH instance", withPassword, (&fakeReader{inst: clusterInstance(memorystorepb.Instance_IAM_AUTH)}).factory(),
			[]Option{WithInstance(testInstance)}},
		{"AuthCredentialsFn, TOKEN_AUTH instance", withFn, (&fakeReader{inst: clusterInstance(memorystorepb.Instance_TOKEN_AUTH)}).factory(),
			[]Option{WithInstance(testInstance)}},
	}
	for _, c := range kept {
		opt, err := resolveOption(t, c.option, c.reader, c.opts...)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if opt.Password != c.option.Password || (opt.AuthCredentialsFn != nil) != (c.option.AuthCredentialsFn != nil) || opt.DialCtxFn != nil {
			t.Errorf("%s: caller credentials not kept as is: fn=%v pw=%q dial gate=%v", c.name, opt.AuthCredentialsFn != nil, opt.Password, opt.DialCtxFn != nil)
			continue
		}
		if opt.AuthCredentialsFn != nil {
			if creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{}); err != nil || creds.Password != "caller-secret" {
				t.Errorf("%s: creds = %+v, %v; want the caller's", c.name, creds, err)
			}
		}
	}
}

// T-CFG-6: every InitAddress and Standalone.ReplicaAddress value is kept as given.
func TestResolve_AddressesKept(t *testing.T) {
	init := []string{"10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"}
	readers := []string{"10.0.1.1:6379", "10.0.1.2:6379"}
	cases := []struct {
		name    string
		readers []string
		opts    []Option
	}{
		{"topology auto", nil, nil},
		{"cluster", nil, []Option{WithTopology(TopologyCluster)}},
		{"cluster disabled", nil, []Option{WithTopology(TopologyClusterDisabled)}},
		{"reader endpoints", readers, nil},
		{"reader endpoints, cluster disabled", readers, []Option{WithTopology(TopologyClusterDisabled)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			option := valkey.ClientOption{InitAddress: slices.Clone(init), Standalone: valkey.StandaloneOption{ReplicaAddress: slices.Clone(c.readers)}}
			opt, err := resolveOption(t, option, noReader(t), c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(opt.InitAddress, init) {
				t.Errorf("InitAddress = %v, want %v", opt.InitAddress, init)
			}
			if !slices.Equal(opt.Standalone.ReplicaAddress, c.readers) {
				t.Errorf("ReplicaAddress = %v, want %v", opt.Standalone.ReplicaAddress, c.readers)
			}
		})
	}
}

// T-CFG-7: the cluster defaults are filled unless the ClientOption has a reader endpoint or
// WithTopology says cluster mode is disabled. Read routing needs a reader endpoint.
func TestResolve_ClusterDefaults(t *testing.T) {
	clusterDefaults := valkey.ClusterOption{PreferInitAddressRefresh: true, ShardsRefreshInterval: defaultShardsRefreshInterval, PreferClusterShards: true}
	withReader := valkey.ClientOption{
		InitAddress: []string{"10.0.0.2:6379"},
		Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}},
	}
	cases := []struct {
		name     string
		option   valkey.ClientOption
		topology Topology
		want     valkey.ClusterOption
		toReader bool // SendToReplicas expected
	}{
		// What NewStandaloneClient(ctx, primary, "") used to configure as an empty reader
		// address: now no reader at all, and the cluster defaults in case it is a cluster.
		{"InitAddress only", initOption("10.0.0.2:6379"), TopologyAuto, clusterDefaults, false},
		{"cluster", initOption("10.0.0.15:6379"), TopologyCluster, clusterDefaults, false},
		{"cluster disabled", initOption("10.0.0.2:6379"), TopologyClusterDisabled, valkey.ClusterOption{}, false},
		{"reader endpoint", withReader, TopologyAuto, valkey.ClusterOption{}, true},
		{"reader endpoint, cluster disabled", withReader, TopologyClusterDisabled, valkey.ClusterOption{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt, err := resolveOption(t, c.option, noReader(t), WithTopology(c.topology))
			if err != nil {
				t.Fatal(err)
			}
			if opt.ClusterOption != c.want {
				t.Errorf("ClusterOption = %+v, want %+v", opt.ClusterOption, c.want)
			}
			if (opt.SendToReplicas != nil) != c.toReader {
				t.Errorf("SendToReplicas set = %v, want %v", opt.SendToReplicas != nil, c.toReader)
			}
			if !c.toReader && len(opt.Standalone.ReplicaAddress) != 0 {
				t.Errorf("ReplicaAddress = %v, want none", opt.Standalone.ReplicaAddress)
			}
		})
	}
}

// Without WithInstance, the auth option passed picks the mechanism.
func TestResolve_AuthFromOptions(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want authMode
		err  string
	}{
		{"nothing", nil, authDisabled, ""},
		{"nil option", []Option{nil}, authDisabled, ""},
		{"token", []Option{WithTokenAuth(TokenAuthOptions{Token: "t"})}, authToken, ""},
		{"iam identity", []Option{WithIAMOptions(staticIAM())}, authIAM, ""},
		{"iam username", []Option{WithIAMOptions(IAMAuthOptions{Username: "u"})}, authIAM, ""},
		{"iam tuning only", []Option{WithIAMOptions(IAMAuthOptions{RefreshBuffer: time.Minute})}, authIAM, ""}, // ADC
		{"default iam", []Option{WithDefaultIAM()}, authIAM, ""},
		{"later WithTokenAuth wins", []Option{WithTokenAuth(TokenAuthOptions{}), WithTokenAuth(TokenAuthOptions{Token: "t"})}, authToken, ""},
		{"both", []Option{WithIAMOptions(staticIAM()), WithTokenAuth(TokenAuthOptions{Token: "t"})}, 0,
			"both WithIAMOptions and WithTokenAuth are set; without WithInstance, pass only one"},
		{"token without source", []Option{WithTokenAuth(TokenAuthOptions{Username: "app"})}, 0, "WithTokenAuth with TokenAuthOptions.SecretVersion"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := append([]Option{WithTLS(TLSOptions{Mode: TLSDisabled})}, c.opts...)
			r, err := resolveWith(initOption("10.0.0.15:6379"), noReader(t), opts...)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("got %v, want error containing %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.auth != c.want {
				t.Fatalf("auth = %v, want %v", r.auth, c.want)
			}
		})
	}
}

func TestResolve_TLSAndTopologyInference(t *testing.T) {
	ca := newTestCA(t, "explicit")
	r, err := resolveWith(initOption("10.0.0.2:6379"), noReader(t), WithTLS(TLSOptions{CAPEM: ca.pem}))
	if err != nil || r.tls != TLSCustomCA || r.topology != TopologyAuto {
		t.Fatalf("got %+v, %v", r, err)
	}
	r, err = resolveWith(initOption("10.0.0.2:6379"), noReader(t), WithTLS(TLSOptions{CAPEM: ca.pem}), WithTopology(TopologyClusterDisabled))
	if err != nil || r.tls != TLSCustomCA || r.topology != TopologyClusterDisabled {
		t.Fatalf("WithTopology(TopologyClusterDisabled): got %+v, %v", r, err)
	}
	if _, err := resolveWith(initOption("p:1"), noReader(t), WithTLS(TLSOptions{ServerName: "x"})); err == nil {
		t.Fatal("TLS options without CA material must fail")
	}
	if _, err := resolveWith(initOption("p:1"), noReader(t), WithTLS(TLSOptions{Mode: TLSPerInstanceCA})); err == nil ||
		!strings.Contains(err.Error(), "WithInstance") {
		t.Fatalf("per-instance CA without WithInstance: %v", err)
	}
	withReader := valkey.ClientOption{InitAddress: []string{"d:1"}, Standalone: valkey.StandaloneOption{ReplicaAddress: []string{"r:1"}}}
	r, err = resolveWith(withReader, noReader(t), WithTopology(TopologyCluster))
	if err == nil || !strings.Contains(err.Error(), "ClientOption.Standalone.ReplicaAddress is for cluster-disabled instances") {
		t.Fatalf("Standalone.ReplicaAddress with TopologyCluster must fail, got %+v, %v", r, err)
	}
	if r, err := resolveWith(initOption("p:1"), noReader(t), WithTopology(TopologyClusterDisabled)); err != nil || r.topology != TopologyClusterDisabled {
		t.Fatalf("InitAddress with TopologyClusterDisabled: %+v, %v", r, err)
	}
	r, err = resolveWith(initOption("a:1"), noReader(t))
	if err != nil || r.topology != TopologyAuto {
		t.Fatalf("ClientOption.InitAddress alone: %+v, %v", r, err)
	}
	for _, c := range []struct {
		opt  Option
		want string
	}{
		{WithTLS(TLSOptions{Mode: TLSMode(9)}), "unknown TLSOptions.Mode TLSMode(9)"},
		{WithTLS(TLSOptions{Mode: TLSMode(-1)}), "unknown TLSOptions.Mode TLSMode(-1)"},
		{WithTopology(Topology(9)), "unknown Topology Topology(9)"},
		{WithTopology(Topology(-1)), "unknown Topology Topology(-1)"},
	} {
		if _, err := resolveWith(initOption("d:1"), noReader(t), c.opt); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("unknown enum accepted: got %v, want %q", err, c.want)
		}
	}
}

func TestResolve_ExplicitTLSAndToken(t *testing.T) {
	ca := newTestCA(t, "explicit")
	var sourceCalls int
	opt, err := resolveOption(t, initOption("10.0.0.2:6379"), noReader(t),
		WithTokenAuth(TokenAuthOptions{Username: "app", Source: func(context.Context) (string, error) {
			sourceCalls++
			return "tok", nil
		}}),
		WithTLS(TLSOptions{CAPEM: ca.pem}),
	)
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
	opt, err := ResolveClientOption(context.Background(), initOption("10.0.0.15:6379"))
	if err != nil || opt.InitAddress[0] != "10.0.0.15:6379" {
		t.Fatalf("got %v, %v", opt.InitAddress, err)
	}
	if opt.Dialer.Timeout != defaultDialTimeout || opt.RetryDelay == nil || !opt.ClusterOption.PreferClusterShards {
		t.Errorf("defaults not filled: dial timeout %v, RetryDelay set %v, ClusterOption %+v", opt.Dialer.Timeout, opt.RetryDelay != nil, opt.ClusterOption)
	}
	if _, err := ResolveClientOption(context.Background(), valkey.ClientOption{}); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewClient(context.Background(), valkey.ClientOption{}); !errors.Is(err, errNoEndpoint) {
		t.Fatalf("NewClient: got %v", err)
	}
}

func TestModeStrings(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{TLSSharedCA.String(), "TLSSharedCA"}, {TLSMode(7).String(), "TLSMode(7)"},
		{TopologyClusterDisabled.String(), "TopologyClusterDisabled"}, {Topology(7).String(), "Topology(7)"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// T-CFG-8: WithNetwork picks one of the instance's PSC endpoints, so it needs WithInstance.
func TestResolve_NetworkNeedsInstance(t *testing.T) {
	_, err := resolveOption(t, initOption("10.0.0.15:6379"), noReader(t), WithNetwork(vpcB))
	if err == nil || !strings.Contains(err.Error(), "WithNetwork needs WithInstance") {
		t.Fatalf("got %v", err)
	}
}

// T-CFG-9: the OnAuth and OnCredentialError options reach the IAM and Token Auth providers
// when IAMAuthOptions or TokenAuthOptions leave their own callback nil; set ones win.
func TestResolve_CallbackOptions(t *testing.T) {
	for _, mech := range []string{"IAM", "Token Auth"} {
		for _, own := range []struct{ onAuth, onErr bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
			t.Run(fmt.Sprintf("%s, own OnAuth %v, own OnCredentialError %v", mech, own.onAuth, own.onErr), func(t *testing.T) {
				var fail atomic.Bool
				var optAuth, optErr, ownAuth, ownErr atomic.Int32
				var onAuth func(AuthEvent)
				var onErr func(error)
				if own.onAuth {
					onAuth = func(AuthEvent) { ownAuth.Add(1) }
				}
				if own.onErr {
					onErr = func(error) { ownErr.Add(1) }
				}
				var authOpt Option
				var wantPassword string
				var cacheWindow time.Duration
				if mech == "IAM" {
					wantPassword = "iam"
					authOpt = WithIAMOptions(IAMAuthOptions{
						CustomTokenSource: tokenSourceFunc(func() (*oauth2.Token, error) {
							if fail.Load() {
								return nil, errors.New("metadata server down")
							}
							// Inside the 5m refresh buffer, so the next AUTH fetches again.
							return &oauth2.Token{AccessToken: "iam", Expiry: time.Now().Add(3 * time.Minute)}, nil
						}),
						OnAuth:            onAuth,
						OnCredentialError: onErr,
					})
				} else {
					wantPassword, cacheWindow = "tok", 30*time.Millisecond // past ReloadInterval/2
					authOpt = WithTokenAuth(TokenAuthOptions{
						ReloadInterval: 40 * time.Millisecond,
						Source: func(context.Context) (string, error) {
							if fail.Load() {
								return "", errors.New("secret manager unavailable")
							}
							return "tok", nil
						},
						OnAuth:            onAuth,
						OnCredentialError: onErr,
					})
				}
				opt, err := resolveOption(t, initOption("10.0.0.2:6379"), noReader(t), authOpt,
					WithTLS(TLSOptions{Mode: TLSDisabled}),
					OnAuth(func(AuthEvent) { optAuth.Add(1) }),
					OnCredentialError(func(error) { optErr.Add(1) }),
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{}); err != nil {
					t.Fatal(err)
				}
				fail.Store(true)
				time.Sleep(cacheWindow)
				creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
				if err != nil || creds.Password != wantPassword {
					t.Fatalf("creds = %+v, %v; want the last token %q", creds, err, wantPassword)
				}
				// Two AUTHs and one absorbed fetch error, each reported to one callback only.
				split := func(ownSet bool, n int32) (int32, int32) {
					if ownSet {
						return n, 0
					}
					return 0, n
				}
				wantOwnAuth, wantOptAuth := split(own.onAuth, 2)
				wantOwnErr, wantOptErr := split(own.onErr, 1)
				if ownAuth.Load() != wantOwnAuth || optAuth.Load() != wantOptAuth {
					t.Errorf("OnAuth calls: own field %d, option %d; want %d, %d", ownAuth.Load(), optAuth.Load(), wantOwnAuth, wantOptAuth)
				}
				if ownErr.Load() != wantOwnErr || optErr.Load() != wantOptErr {
					t.Errorf("OnCredentialError calls: own field %d, option %d; want %d, %d", ownErr.Load(), optErr.Load(), wantOwnErr, wantOptErr)
				}
			})
		}
	}
}

// NewClient stops before dialing when ctx ended during setup (valkey.NewClient takes no context).
func TestNewClient_ContextEndedBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewClient(ctx, initOption("127.0.0.1:0")); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}
