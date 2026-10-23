package valkeygcp

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	vpcA = "projects/my-proj/global/networks/vpc-a"
	vpcB = "projects/my-proj/global/networks/vpc-b"
)

func clusterInstance(auth memorystorepb.Instance_AuthorizationMode) *memorystorepb.Instance {
	return &memorystorepb.Instance{
		Name:              testInstance,
		Mode:              memorystorepb.Instance_CLUSTER,
		AuthorizationMode: auth,
		Endpoints: []*memorystorepb.Instance_InstanceEndpoint{endpointGroup(
			autoConn("10.0.0.15", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, vpcA),
		)},
	}
}

// clusterDisabledInstance is a cluster-disabled instance with a primary and a reader endpoint.
func clusterDisabledInstance(auth memorystorepb.Instance_AuthorizationMode) *memorystorepb.Instance {
	return &memorystorepb.Instance{
		Name:              testInstance,
		Mode:              memorystorepb.Instance_CLUSTER_DISABLED,
		AuthorizationMode: auth,
		Endpoints: []*memorystorepb.Instance_InstanceEndpoint{endpointGroup(
			autoConn("10.0.0.2", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY, vpcA),
			autoConn("10.0.0.3", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_READER, vpcA),
		)},
	}
}

// T-DISC-1
func TestResolve_DiscoverClusterIAMPerInstanceCA(t *testing.T) {
	ca1, ca2 := newTestCA(t, "ca-1"), newTestCA(t, "ca-2")
	inst := clusterInstance(memorystorepb.Instance_IAM_AUTH)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_GOOGLE_MANAGED_PER_INSTANCE_CA.Enum()
	fake := &fakeReader{inst: inst, perCA: []string{string(ca1.pem), string(ca2.pem)}}

	r, err := resolveWith(valkey.ClientOption{}, fake.factory(), WithInstance(testInstance), WithIAMOptions(staticIAM()))
	if err != nil {
		t.Fatal(err)
	}
	if r.auth != authIAM || r.tls != TLSPerInstanceCA || r.topology != TopologyCluster {
		t.Fatalf("resolved %v/%v/%v", r.auth, r.tls, r.topology)
	}
	if fake.gotName != testInstance || fake.perCalls != 1 || fake.perName != testInstance || fake.sharedCalls != 0 {
		t.Fatalf("calls: get=%q per=%d(%q) shared=%d", fake.gotName, fake.perCalls, fake.perName, fake.sharedCalls)
	}
	if !fake.closed {
		t.Error("control-plane client not closed after resolution")
	}
	opt, err := r.clientOption(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opt.InitAddress[0] != "10.0.0.15:6379" || opt.TLSConfig == nil || opt.AuthCredentialsFn == nil {
		t.Fatalf("option: %v tls=%v auth=%v", opt.InitAddress, opt.TLSConfig != nil, opt.AuthCredentialsFn != nil)
	}
	if fake.perCalls != 1 {
		t.Errorf("PerInstanceCA called %d times", fake.perCalls)
	}
}

// T-DISC-2
func TestResolve_DiscoverClusterDisabledTokenSharedCA(t *testing.T) {
	ca := newTestCA(t, "regional")
	inst := clusterDisabledInstance(memorystorepb.Instance_TOKEN_AUTH)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_GOOGLE_MANAGED_SHARED_CA.Enum()
	fake := &fakeReader{inst: inst, sharedCA: []string{string(ca.pem)}}
	r, err := resolveWith(valkey.ClientOption{}, fake.factory(),
		WithInstance(testInstance),
		WithIAMOptions(staticIAM()), // ignored: the instance decides
		WithTokenAuth(TokenAuthOptions{Token: "tok"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if r.auth != authToken || r.tls != TLSSharedCA || r.topology != TopologyClusterDisabled {
		t.Fatalf("resolved %v/%v/%v", r.auth, r.tls, r.topology)
	}
	if fake.sharedCalls != 1 || fake.sharedProject != "my-proj" || fake.sharedRegion != "us-west4" || fake.perCalls != 0 {
		t.Fatalf("shared CA call: %d %q %q (per=%d)", fake.sharedCalls, fake.sharedProject, fake.sharedRegion, fake.perCalls)
	}
	opt, err := r.clientOption(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if opt.InitAddress[0] != "10.0.0.2:6379" || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" || opt.SendToReplicas == nil {
		t.Fatalf("endpoints: %v %v", opt.InitAddress, opt.Standalone.ReplicaAddress)
	}
	if opt.ClusterOption.PreferInitAddressRefresh || opt.ClusterOption.ShardsRefreshInterval != 0 {
		t.Errorf("cluster defaults set for a cluster-disabled instance: %+v", opt.ClusterOption)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != "" || creds.Password != "tok" {
		t.Fatalf("token creds = %+v, %v", creds, err)
	}
}

// T-DISC-3
func TestResolve_DiscoverNoAuthNoTLS(t *testing.T) {
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED
	fake := &fakeReader{inst: inst}
	opt, err := resolveOption(t, valkey.ClientOption{}, fake.factory(), WithInstance(testInstance), WithIAMOptions(staticIAM()))
	if err != nil {
		t.Fatal(err)
	}
	if opt.AuthCredentialsFn != nil || opt.TLSConfig != nil || fake.perCalls+fake.sharedCalls != 0 {
		t.Fatalf("auth=%v tls=%v caCalls=%d", opt.AuthCredentialsFn != nil, opt.TLSConfig != nil, fake.perCalls+fake.sharedCalls)
	}
}

// T-DISC-4
func TestResolve_DiscoverContradictions(t *testing.T) {
	cases := []struct {
		name   string
		option valkey.ClientOption
		opts   []Option
		want   string
	}{
		{"tls", valkey.ClientOption{}, []Option{WithTLS(TLSOptions{Mode: TLSSharedCA})}, "instance uses TRANSIT_ENCRYPTION_DISABLED but WithTLS sets Mode TLSSharedCA"},
		{"topology", valkey.ClientOption{}, []Option{WithTopology(TopologyClusterDisabled)}, "instance mode is CLUSTER but WithTopology is TopologyClusterDisabled"},
		{"reader endpoint", valkey.ClientOption{Standalone: valkey.StandaloneOption{ReplicaAddress: []string{"10.9.9.9:6379"}}}, nil,
			"Standalone.ReplicaAddress is for cluster-disabled instances, but the topology is cluster"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst := clusterInstance(memorystorepb.Instance_IAM_AUTH)
			inst.TransitEncryptionMode = memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED
			_, err := resolveWith(c.option, (&fakeReader{inst: inst}).factory(), append([]Option{WithInstance(testInstance)}, c.opts...)...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// T-DISC-5
func TestResolve_DiscoverTokenAuthWithoutSource(t *testing.T) {
	for name, opts := range map[string][]Option{
		"no token option":        {WithIAMOptions(staticIAM())},
		"token option no source": {WithTokenAuth(TokenAuthOptions{Username: "app"})},
	} {
		fake := &fakeReader{inst: clusterInstance(memorystorepb.Instance_TOKEN_AUTH)}
		_, err := resolveWith(valkey.ClientOption{}, fake.factory(), append([]Option{WithInstance(testInstance)}, opts...)...)
		if !errors.Is(err, errNoTokenSource) || !strings.Contains(err.Error(), "TokenAuthOptions.SecretVersion") {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

// T-DISC-6
func TestResolve_DiscoverPermissionDenied(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "Permission 'memorystore.instances.get' denied")
	_, err := resolveWith(valkey.ClientOption{}, (&fakeReader{getErr: denied}).factory(), WithInstance(testInstance))
	if err == nil || !strings.Contains(err.Error(), "memorystore.instances.get") || !strings.Contains(err.Error(), "roles/memorystore.viewer") {
		t.Fatalf("got %v", err)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("gRPC status lost in wrapping: %v", status.Code(err))
	}

	// CA download needs the same permission.
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	_, err = resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst, caErr: denied}).factory(), WithInstance(testInstance))
	if err == nil || !strings.Contains(err.Error(), "roles/memorystore.viewer") || !strings.Contains(err.Error(), "server CA") {
		t.Fatalf("CA download: got %v", err)
	}

	// Other errors pass through without the permission hint.
	_, err = resolveWith(valkey.ClientOption{}, (&fakeReader{getErr: status.Error(codes.NotFound, "no such instance")}).factory(), WithInstance(testInstance))
	if err == nil || strings.Contains(err.Error(), "roles/memorystore.viewer") {
		t.Fatalf("NotFound: got %v", err)
	}

	// The reader factory's own error is returned as is.
	boom := errors.New("no ADC")
	_, err = resolveWith(valkey.ClientOption{}, func(context.Context) (instanceReader, error) { return nil, boom }, WithInstance(testInstance))
	if !errors.Is(err, boom) {
		t.Fatalf("factory error: got %v", err)
	}
}

// T-DISC-7
func TestResolve_DiscoverNetworkSelection(t *testing.T) {
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.Endpoints = []*memorystorepb.Instance_InstanceEndpoint{
		endpointGroup(autoConn("10.0.0.15", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, vpcA)),
		endpointGroup(userConn("10.1.0.15", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, vpcB)),
	}
	for network, want := range map[string]string{
		"":   "10.0.0.15:6379",
		vpcB: "10.1.0.15:6379",
		"https://www.googleapis.com/compute/v1/" + vpcB: "10.1.0.15:6379",
		"vpc-b": "10.1.0.15:6379",
	} {
		r, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance), WithNetwork(network))
		if err != nil || r.discovery != want {
			t.Errorf("network %q: got %q, %v; want %q", network, r.discovery, err, want)
		}
	}
	_, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance), WithNetwork("vpc-c"))
	if err == nil || !strings.Contains(err.Error(), `in network "vpc-c"`) {
		t.Fatalf("unknown network: got %v", err)
	}
}

// T-DISC-8
func TestResolve_DiscoverDeprecatedDiscoveryEndpoints(t *testing.T) {
	inst := &memorystorepb.Instance{
		Mode:               memorystorepb.Instance_CLUSTER,
		DiscoveryEndpoints: []*memorystorepb.DiscoveryEndpoint{{Address: "10.0.0.20", Port: 6380, Network: vpcA}}, //nolint:staticcheck // SA1019: covers the fallback for the deprecated field
	}
	r, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance))
	if err != nil || r.discovery != "10.0.0.20:6380" {
		t.Fatalf("got %q, %v", r.discovery, err)
	}
}

// T-DISC-9
func TestResolve_DiscoverCustomerManagedCANeedsPEM(t *testing.T) {
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_CUSTOMER_MANAGED_CAS_CA.Enum()
	fake := &fakeReader{inst: inst}
	_, err := resolveWith(valkey.ClientOption{}, fake.factory(), WithInstance(testInstance))
	if err == nil || !strings.Contains(err.Error(), "needs CA certificates") || !strings.Contains(err.Error(), "TLSOptions.FetchCustomCA") || strings.Contains(err.Error(), "download them") {
		t.Fatalf("got %v", err)
	}
	if fake.perCalls+fake.sharedCalls != 0 {
		t.Error("customer-managed CAs can't be downloaded; no CA call expected")
	}
	ca := newTestCA(t, "cas-root")
	opt, err := resolveOption(t, valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance), WithTLS(TLSOptions{CAPEM: ca.pem}))
	if err != nil || opt.TLSConfig == nil {
		t.Fatalf("with CAPEM: %v", err)
	}
}

// T-DISC-10
func TestResolve_DiscoverUnspecifiedCAModeIsPerInstance(t *testing.T) {
	ca := newTestCA(t, "legacy")
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_SERVER_CA_MODE_UNSPECIFIED.Enum()
	fake := &fakeReader{inst: inst, perCA: []string{string(ca.pem)}}
	r, err := resolveWith(valkey.ClientOption{}, fake.factory(), WithInstance(testInstance))
	if err != nil || r.tls != TLSPerInstanceCA || fake.perCalls != 1 {
		t.Fatalf("got %v, %v (per=%d)", r.tls, err, fake.perCalls)
	}
}

// T-DISC-11
func TestResolve_DiscoverPortZeroDefaults(t *testing.T) {
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.Endpoints = []*memorystorepb.Instance_InstanceEndpoint{endpointGroup(
		autoConn("10.0.0.15", 0, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, vpcA),
	)}
	r, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance))
	if err != nil || r.discovery != "10.0.0.15:6379" {
		t.Fatalf("got %q, %v", r.discovery, err)
	}
}

// T-DISC-13: the instance fills only what the ClientOption leaves empty.
func TestResolve_DiscoverFillsOnlyEmptyFields(t *testing.T) {
	newFake := func() *fakeReader {
		return &fakeReader{inst: clusterDisabledInstance(memorystorepb.Instance_AUTH_DISABLED)}
	}
	cases := []struct {
		name        string
		option      valkey.ClientOption
		wantInit    []string
		wantReplica []string
	}{
		{"empty option", valkey.ClientOption{}, []string{"10.0.0.2:6379"}, []string{"10.0.0.3:6379"}},
		{"caller InitAddress", valkey.ClientOption{InitAddress: []string{"proxy:6379"}}, []string{"proxy:6379"}, []string{"10.0.0.3:6379"}},
		{"caller ReplicaAddress", valkey.ClientOption{Standalone: valkey.StandaloneOption{ReplicaAddress: []string{"r1:6379", "r2:6379"}}},
			[]string{"10.0.0.2:6379"}, []string{"r1:6379", "r2:6379"}},
		{"EnableRedirect keeps the reader out", valkey.ClientOption{Standalone: valkey.StandaloneOption{EnableRedirect: true}},
			[]string{"10.0.0.2:6379"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opt, err := resolveOption(t, c.option, newFake().factory(), WithInstance(testInstance))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(opt.InitAddress, ",") != strings.Join(c.wantInit, ",") ||
				strings.Join(opt.Standalone.ReplicaAddress, ",") != strings.Join(c.wantReplica, ",") {
				t.Fatalf("InitAddress %v, ReplicaAddress %v; want %v, %v", opt.InitAddress, opt.Standalone.ReplicaAddress, c.wantInit, c.wantReplica)
			}
			if (len(c.wantReplica) > 0) != (opt.SendToReplicas != nil) {
				t.Errorf("SendToReplicas set %v with replicas %v", opt.SendToReplicas != nil, c.wantReplica)
			}
		})
	}
}

// T-DISC-14: with both auth options, the instance's auth mode picks one; an IAM_AUTH
// instance without an IAM option uses Application Default Credentials.
func TestResolve_DiscoverInstancePicksAuth(t *testing.T) {
	both := []Option{WithInstance(testInstance), WithIAMOptions(staticIAM()), WithTokenAuth(TokenAuthOptions{Token: "tok"})}
	for mode, want := range map[memorystorepb.Instance_AuthorizationMode]string{
		memorystorepb.Instance_IAM_AUTH:      "iam-token",
		memorystorepb.Instance_TOKEN_AUTH:    "tok",
		memorystorepb.Instance_AUTH_DISABLED: "",
	} {
		inst := clusterInstance(mode)
		opt, err := resolveOption(t, valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), both...)
		if err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		var got string
		if opt.AuthCredentialsFn != nil {
			creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
			if err != nil {
				t.Fatalf("%v: %v", mode, err)
			}
			got = creds.Password
		}
		if got != want {
			t.Errorf("%v: AUTH password %q, want %q", mode, got, want)
		}
	}

	// A credentials file that doesn't exist makes ADC fail at once, without probing the
	// metadata server.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	_, err := resolveOption(t, valkey.ClientOption{}, (&fakeReader{inst: clusterInstance(memorystorepb.Instance_IAM_AUTH)}).factory(),
		WithInstance(testInstance), WithTokenAuth(TokenAuthOptions{Token: "tok"}))
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("IAM_AUTH without an IAM option: got %v, want the ADC error", err)
	}
}

func TestResolve_DiscoverEdgeCases(t *testing.T) {
	t.Run("malformed instance name", func(t *testing.T) {
		for _, name := range []string{"my-valkey", "projects/p/locations/r/clusters/c", "projects//locations/r/instances/i", testInstance + "/x"} {
			if _, err := resolveWith(valkey.ClientOption{}, noReader(t), WithInstance(name)); err == nil {
				t.Errorf("%q accepted", name)
			}
		}
	})
	t.Run("caller InitAddress overrides discovery", func(t *testing.T) {
		opt, err := resolveOption(t, initOption("proxy:6379"),
			(&fakeReader{inst: clusterInstance(memorystorepb.Instance_AUTH_DISABLED)}).factory(), WithInstance(testInstance))
		if err != nil || len(opt.InitAddress) != 1 || opt.InitAddress[0] != "proxy:6379" {
			t.Fatalf("got %v, %v", opt.InitAddress, err)
		}
	})
	t.Run("no PSC endpoint yet", func(t *testing.T) {
		_, err := resolveWith(valkey.ClientOption{},
			(&fakeReader{inst: &memorystorepb.Instance{Mode: memorystorepb.Instance_CLUSTER}}).factory(), WithInstance(testInstance))
		if err == nil || !strings.Contains(err.Error(), "CONNECTION_TYPE_DISCOVERY") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("explicit TLSCustomCA on a Google-managed CA", func(t *testing.T) {
		ca := newTestCA(t, "offline-bundle")
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
		fake := &fakeReader{inst: inst}
		r, err := resolveWith(valkey.ClientOption{}, fake.factory(), WithInstance(testInstance), WithTLS(TLSOptions{Mode: TLSCustomCA, CAPEM: ca.pem}))
		if err != nil || r.tls != TLSCustomCA || fake.perCalls != 0 {
			t.Fatalf("got %v, %v (per=%d)", r.tls, err, fake.perCalls)
		}
	})
	t.Run("caller TLSConfig on a plain-text instance", func(t *testing.T) {
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED
		_, err := resolveWith(valkey.ClientOption{TLSConfig: &tls.Config{}}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance))
		if err == nil || !strings.Contains(err.Error(), "in-transit encryption disabled") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("API returns no CA certificate", func(t *testing.T) {
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
		_, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance))
		if err == nil || !strings.Contains(err.Error(), "no server CA certificate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("legacy STANDALONE mode", func(t *testing.T) {
		inst := &memorystorepb.Instance{
			Mode: memorystorepb.Instance_Mode(1), // STANDALONE, the deprecated name of CLUSTER_DISABLED
			Endpoints: []*memorystorepb.Instance_InstanceEndpoint{endpointGroup(
				autoConn("10.0.0.2", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY, ""),
			)},
		}
		r, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance))
		if err != nil || r.topology != TopologyClusterDisabled || r.primary != "10.0.0.2:6379" || r.reader != "" {
			t.Fatalf("got %+v, %v", r, err)
		}
	})
	t.Run("unknown enum values", func(t *testing.T) {
		for _, inst := range []*memorystorepb.Instance{
			{Mode: memorystorepb.Instance_Mode(99)},
			{AuthorizationMode: memorystorepb.Instance_AuthorizationMode(99)},
			{TransitEncryptionMode: memorystorepb.Instance_TransitEncryptionMode(99)},
			{TransitEncryptionMode: memorystorepb.Instance_SERVER_AUTHENTICATION, ServerCaMode: memorystorepb.Instance_ServerCaMode(99).Enum()},
		} {
			if _, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: inst}).factory(), WithInstance(testInstance)); err == nil ||
				!strings.Contains(err.Error(), "unsupported") {
				t.Errorf("%v accepted: %v", inst, err)
			}
		}
	})
}

// cmcaInstance is a cluster instance whose server CA is a customer-managed CA Service pool.
func cmcaInstance(pool string) *memorystorepb.Instance {
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_CUSTOMER_MANAGED_CAS_CA.Enum()
	if pool != "" {
		inst.ServerCaPool = &pool
	}
	return inst
}

// T-DISC-12 (U11): with TLSOptions.FetchCustomCA, a customer-managed CA instance is configured
// from WithInstance alone: the CA comes from the instance's CA pool.
func TestResolve_DiscoverCustomerManagedCAFetch(t *testing.T) {
	const pool = "projects/my-proj/locations/us-west4/caPools/valkey-pool"
	ca := newTestCA(t, "cas")
	var gotPool string
	fetch := func(_ context.Context, p string) ([]string, error) {
		gotPool = p
		return []string{string(ca.pem)}, nil
	}
	fake := &fakeReader{inst: cmcaInstance(pool)}
	opt, err := resolveOption(t, valkey.ClientOption{}, fake.factory(), WithInstance(testInstance), WithTLS(TLSOptions{FetchCustomCA: fetch}))
	if err != nil {
		t.Fatal(err)
	}
	if gotPool != pool {
		t.Errorf("FetchCustomCA got pool %q, want %q", gotPool, pool)
	}
	if opt.TLSConfig == nil || opt.TLSConfig.RootCAs == nil {
		t.Fatal("TLSConfig with the CA pool's certificates expected")
	}
	if fake.perCalls+fake.sharedCalls != 0 {
		t.Error("no Memorystore CA call expected for a customer-managed CA")
	}

	// Caller CA material wins: the pool isn't read.
	gotPool = ""
	if _, err := resolveOption(t, valkey.ClientOption{}, (&fakeReader{inst: cmcaInstance(pool)}).factory(),
		WithInstance(testInstance), WithTLS(TLSOptions{FetchCustomCA: fetch, CAPEM: ca.pem})); err != nil || gotPool != "" {
		t.Fatalf("got %v, pool read %q; want CAPEM used without a fetch", err, gotPool)
	}
}

func TestResolve_DiscoverCustomerManagedCAFetchErrors(t *testing.T) {
	const pool = "projects/p/locations/l/caPools/x"
	cases := []struct {
		name  string
		inst  *memorystorepb.Instance
		fetch func(context.Context, string) ([]string, error)
		want  string
	}{
		{"no pool", cmcaInstance(""), func(context.Context, string) ([]string, error) { return nil, nil }, "no server_ca_pool"},
		{"fetch error", cmcaInstance(pool), func(context.Context, string) ([]string, error) { return nil, errors.New("403") }, "privateca.caPools.get"},
		{"empty pool", cmcaInstance(pool), func(context.Context, string) ([]string, error) { return nil, nil }, "returned no CA certificate"},
	}
	for _, c := range cases {
		_, err := resolveWith(valkey.ClientOption{}, (&fakeReader{inst: c.inst}).factory(), WithInstance(testInstance), WithTLS(TLSOptions{FetchCustomCA: c.fetch}))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}
