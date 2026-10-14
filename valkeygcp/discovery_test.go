package valkeygcp

import (
	"context"
	"crypto/tls"
	"errors"
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

// T-DISC-1
func TestResolve_DiscoverClusterIAMPerInstanceCA(t *testing.T) {
	ca1, ca2 := newTestCA(t, "ca-1"), newTestCA(t, "ca-2")
	inst := clusterInstance(memorystorepb.Instance_IAM_AUTH)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	inst.ServerCaMode = memorystorepb.Instance_GOOGLE_MANAGED_PER_INSTANCE_CA.Enum()
	fake := &fakeReader{inst: inst, perCA: []string{string(ca1.pem), string(ca2.pem)}}

	r, err := resolve(context.Background(), Config{Instance: testInstance, Auth: AuthOptions{IAM: staticIAM()}}, fake.factory())
	if err != nil {
		t.Fatal(err)
	}
	if r.auth != AuthIAM || r.tls != TLSPerInstanceCA || r.topology != TopologyCluster {
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
	inst := &memorystorepb.Instance{
		Mode:                  memorystorepb.Instance_CLUSTER_DISABLED,
		AuthorizationMode:     memorystorepb.Instance_TOKEN_AUTH,
		TransitEncryptionMode: memorystorepb.Instance_SERVER_AUTHENTICATION,
		ServerCaMode:          memorystorepb.Instance_GOOGLE_MANAGED_SHARED_CA.Enum(),
		Endpoints: []*memorystorepb.Instance_InstanceEndpoint{endpointGroup(
			autoConn("10.0.0.2", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY, vpcA),
			autoConn("10.0.0.3", 6379, memorystorepb.ConnectionType_CONNECTION_TYPE_READER, vpcA),
		)},
	}
	fake := &fakeReader{inst: inst, sharedCA: []string{string(ca.pem)}}
	cfg := Config{Instance: testInstance, Auth: AuthOptions{
		IAM:   staticIAM(), // ignored: the instance decides
		Token: TokenAuthOptions{Token: "tok"},
	}}
	r, err := resolve(context.Background(), cfg, fake.factory())
	if err != nil {
		t.Fatal(err)
	}
	if r.auth != AuthToken || r.tls != TLSSharedCA || r.topology != TopologyClusterDisabled {
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
	opt, err := resolveOption(t, Config{Instance: testInstance, Auth: AuthOptions{IAM: staticIAM()}}, fake.factory())
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
		name string
		cfg  Config
		want string
	}{
		{"auth", Config{Auth: AuthOptions{Mode: AuthToken, Token: TokenAuthOptions{Token: "t"}}}, "instance uses IAM_AUTH but Auth.Mode is AuthToken"},
		{"tls", Config{TLS: TLSOptions{Mode: TLSSharedCA}}, "instance uses TRANSIT_ENCRYPTION_DISABLED but TLS.Mode is TLSSharedCA"},
		{"topology", Config{Topology: TopologyClusterDisabled}, "instance mode is CLUSTER but Topology is TopologyClusterDisabled"},
		{"endpoint", Config{PrimaryEndpoint: "10.9.9.9:6379"}, "PrimaryEndpoint and ReaderEndpoint are for cluster-disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst := clusterInstance(memorystorepb.Instance_IAM_AUTH)
			inst.TransitEncryptionMode = memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED
			c.cfg.Instance = testInstance
			_, err := resolve(context.Background(), c.cfg, (&fakeReader{inst: inst}).factory())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// T-DISC-5
func TestResolve_DiscoverTokenAuthWithoutSource(t *testing.T) {
	fake := &fakeReader{inst: clusterInstance(memorystorepb.Instance_TOKEN_AUTH)}
	_, err := resolve(context.Background(), Config{Instance: testInstance, Auth: AuthOptions{IAM: staticIAM()}}, fake.factory())
	if !errors.Is(err, errNoTokenSource) || !strings.Contains(err.Error(), "Auth.Token.SecretVersion") {
		t.Fatalf("got %v", err)
	}
}

// T-DISC-6
func TestResolve_DiscoverPermissionDenied(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "Permission 'memorystore.instances.get' denied")
	_, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{getErr: denied}).factory())
	if err == nil || !strings.Contains(err.Error(), "memorystore.instances.get") || !strings.Contains(err.Error(), "roles/memorystore.viewer") {
		t.Fatalf("got %v", err)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("gRPC status lost in wrapping: %v", status.Code(err))
	}

	// CA download needs the same permission.
	inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
	inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
	_, err = resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst, caErr: denied}).factory())
	if err == nil || !strings.Contains(err.Error(), "roles/memorystore.viewer") || !strings.Contains(err.Error(), "server CA") {
		t.Fatalf("CA download: got %v", err)
	}

	// Other errors pass through without the permission hint.
	_, err = resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{getErr: status.Error(codes.NotFound, "no such instance")}).factory())
	if err == nil || strings.Contains(err.Error(), "roles/memorystore.viewer") {
		t.Fatalf("NotFound: got %v", err)
	}

	// The reader factory's own error is returned as is.
	boom := errors.New("no ADC")
	_, err = resolve(context.Background(), Config{Instance: testInstance}, func(context.Context) (instanceReader, error) { return nil, boom })
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
		r, err := resolve(context.Background(), Config{Instance: testInstance, Network: network}, (&fakeReader{inst: inst}).factory())
		if err != nil || r.discovery != want {
			t.Errorf("network %q: got %q, %v; want %q", network, r.discovery, err, want)
		}
	}
	_, err := resolve(context.Background(), Config{Instance: testInstance, Network: "vpc-c"}, (&fakeReader{inst: inst}).factory())
	if err == nil || !strings.Contains(err.Error(), `in network "vpc-c"`) {
		t.Fatalf("unknown network: got %v", err)
	}
}

// T-DISC-8
func TestResolve_DiscoverDeprecatedDiscoveryEndpoints(t *testing.T) {
	inst := &memorystorepb.Instance{
		Mode:               memorystorepb.Instance_CLUSTER,
		DiscoveryEndpoints: []*memorystorepb.DiscoveryEndpoint{{Address: "10.0.0.20", Port: 6380, Network: vpcA}},
	}
	r, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst}).factory())
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
	_, err := resolve(context.Background(), Config{Instance: testInstance}, fake.factory())
	if err == nil || !strings.Contains(err.Error(), "needs CA certificates") || strings.Contains(err.Error(), "Config.Instance") {
		t.Fatalf("got %v", err)
	}
	if fake.perCalls+fake.sharedCalls != 0 {
		t.Error("customer-managed CAs can't be downloaded; no CA call expected")
	}
	ca := newTestCA(t, "cas-root")
	opt, err := resolveOption(t, Config{Instance: testInstance, TLS: TLSOptions{CAPEM: ca.pem}}, (&fakeReader{inst: inst}).factory())
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
	r, err := resolve(context.Background(), Config{Instance: testInstance}, fake.factory())
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
	r, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst}).factory())
	if err != nil || r.discovery != "10.0.0.15:6379" {
		t.Fatalf("got %q, %v", r.discovery, err)
	}
}

func TestResolve_DiscoverEdgeCases(t *testing.T) {
	t.Run("malformed instance name", func(t *testing.T) {
		for _, name := range []string{"my-valkey", "projects/p/locations/r/clusters/c", "projects//locations/r/instances/i", testInstance + "/x"} {
			if _, err := resolve(context.Background(), Config{Instance: name}, noReader(t)); err == nil {
				t.Errorf("%q accepted", name)
			}
		}
	})
	t.Run("explicit endpoint overrides discovery", func(t *testing.T) {
		r, err := resolve(context.Background(), Config{Instance: testInstance, DiscoveryEndpoint: "proxy:6379"},
			(&fakeReader{inst: clusterInstance(memorystorepb.Instance_AUTH_DISABLED)}).factory())
		if err != nil || r.discovery != "proxy:6379" {
			t.Fatalf("got %q, %v", r.discovery, err)
		}
	})
	t.Run("no PSC endpoint yet", func(t *testing.T) {
		_, err := resolve(context.Background(), Config{Instance: testInstance},
			(&fakeReader{inst: &memorystorepb.Instance{Mode: memorystorepb.Instance_CLUSTER}}).factory())
		if err == nil || !strings.Contains(err.Error(), "CONNECTION_TYPE_DISCOVERY") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("explicit TLSCustomCA on a Google-managed CA", func(t *testing.T) {
		ca := newTestCA(t, "offline-bundle")
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
		fake := &fakeReader{inst: inst}
		r, err := resolve(context.Background(), Config{Instance: testInstance, TLS: TLSOptions{Mode: TLSCustomCA, CAPEM: ca.pem}}, fake.factory())
		if err != nil || r.tls != TLSCustomCA || fake.perCalls != 0 {
			t.Fatalf("got %v, %v (per=%d)", r.tls, err, fake.perCalls)
		}
	})
	t.Run("caller TLSConfig on a plain-text instance", func(t *testing.T) {
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED
		cfg := Config{Instance: testInstance}
		cfg.ClientOption.TLSConfig = &tls.Config{}
		_, err := resolve(context.Background(), cfg, (&fakeReader{inst: inst}).factory())
		if err == nil || !strings.Contains(err.Error(), "in-transit encryption disabled") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("API returns no CA certificate", func(t *testing.T) {
		inst := clusterInstance(memorystorepb.Instance_AUTH_DISABLED)
		inst.TransitEncryptionMode = memorystorepb.Instance_SERVER_AUTHENTICATION
		_, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst}).factory())
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
		r, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst}).factory())
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
			if _, err := resolve(context.Background(), Config{Instance: testInstance}, (&fakeReader{inst: inst}).factory()); err == nil ||
				!strings.Contains(err.Error(), "unsupported") {
				t.Errorf("%v accepted: %v", inst, err)
			}
		}
	})
}
