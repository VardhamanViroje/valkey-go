package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	memorystore "cloud.google.com/go/memorystore/apiv1"
	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errNoEndpoint = errors.New("valkeygcp: no endpoint: set Instance, DiscoveryEndpoint or PrimaryEndpoint")

// instanceReader is the minimal control-plane surface; tests inject a fake.
type instanceReader interface {
	GetInstance(ctx context.Context, name string) (*memorystorepb.Instance, error)
	PerInstanceCA(ctx context.Context, name string) ([]string, error)               // PEM certificates
	SharedRegionalCA(ctx context.Context, project, region string) ([]string, error) // PEM certificates
	Close() error
}

type apiReader struct{ c *memorystore.Client }

func defaultInstanceReader(ctx context.Context) (instanceReader, error) {
	c, err := memorystore.NewClient(ctx) // ADC; needs memorystore.instances.get
	if err != nil {
		return nil, fmt.Errorf("valkeygcp: memorystore API client: %w", err)
	}
	return &apiReader{c: c}, nil
}

func (a *apiReader) GetInstance(ctx context.Context, name string) (*memorystorepb.Instance, error) {
	return a.c.GetInstance(ctx, &memorystorepb.GetInstanceRequest{Name: name})
}

func (a *apiReader) PerInstanceCA(ctx context.Context, name string) ([]string, error) {
	ca, err := a.c.GetCertificateAuthority(ctx, &memorystorepb.GetCertificateAuthorityRequest{Name: name})
	if err != nil {
		return nil, err
	}
	var pems []string
	for _, chain := range ca.GetManagedServerCa().GetCaCerts() { // every chain: covers CA overlap (Q4)
		pems = append(pems, chain.GetCertificates()...)
	}
	return pems, nil
}

func (a *apiReader) SharedRegionalCA(ctx context.Context, project, region string) ([]string, error) {
	name := fmt.Sprintf("projects/%s/locations/%s/sharedRegionalCertificateAuthority", project, region)
	ca, err := a.c.GetSharedRegionalCertificateAuthority(ctx,
		&memorystorepb.GetSharedRegionalCertificateAuthorityRequest{Name: name})
	if err != nil {
		return nil, err
	}
	var pems []string
	for _, chain := range ca.GetManagedServerCa().GetCaCerts() {
		pems = append(pems, chain.GetCertificates()...)
	}
	return pems, nil
}

func (a *apiReader) Close() error { return a.c.Close() }

// parseInstanceName splits "projects/P/locations/R/instances/I".
func parseInstanceName(name string) (project, region string, err error) {
	p := strings.Split(name, "/")
	if len(p) != 6 || p[0] != "projects" || p[2] != "locations" || p[4] != "instances" ||
		p[1] == "" || p[3] == "" || p[5] == "" {
		return "", "", fmt.Errorf("valkeygcp: Instance must be projects/P/locations/R/instances/I, got %q", name)
	}
	return p[1], p[3], nil
}

type pscEndpoint struct {
	addr    string
	typ     memorystorepb.ConnectionType
	network string
}

// pscEndpoints flattens endpoints[].connections[] (auto or user-created PSC) and falls
// back to the deprecated discovery_endpoints field.
func pscEndpoints(inst *memorystorepb.Instance) []pscEndpoint {
	var out []pscEndpoint
	add := func(ip string, port int32, typ memorystorepb.ConnectionType, network string) {
		if ip == "" {
			return
		}
		if port == 0 {
			port = 6379
		}
		out = append(out, pscEndpoint{net.JoinHostPort(ip, strconv.Itoa(int(port))), typ, network})
	}
	for _, group := range inst.GetEndpoints() {
		for _, c := range group.GetConnections() {
			if a := c.GetPscAutoConnection(); a != nil {
				add(a.GetIpAddress(), a.GetPort(), a.GetConnectionType(), a.GetNetwork())
			} else if u := c.GetPscConnection(); u != nil {
				add(u.GetIpAddress(), u.GetPort(), u.GetConnectionType(), u.GetNetwork())
			}
		}
	}
	//lint:ignore SA1019 fallback for instances whose endpoints[] field is empty
	for _, d := range inst.GetDiscoveryEndpoints() {
		add(d.GetAddress(), d.GetPort(), memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, d.GetNetwork())
	}
	return out
}

func pickEndpoint(eps []pscEndpoint, typ memorystorepb.ConnectionType, network string) string {
	for _, e := range eps {
		if e.typ == typ && (network == "" || e.network == "" || sameNetwork(e.network, network)) {
			return e.addr
		}
	}
	return ""
}

// sameNetwork compares VPC network names given as a URL, as
// "projects/P/global/networks/N", or as the bare name N.
func sameNetwork(a, b string) bool {
	a, b = trimNetworkURL(a), trimNetworkURL(b)
	if a == b {
		return true
	}
	if !strings.Contains(a, "/") || !strings.Contains(b, "/") {
		return a[strings.LastIndex(a, "/")+1:] == b[strings.LastIndex(b, "/")+1:]
	}
	return false
}

func trimNetworkURL(n string) string {
	if i := strings.Index(n, "projects/"); i >= 0 {
		return n[i:]
	}
	return n
}

// resolve applies §1.5: explicit Config value, then the value discovered from the instance,
// then a safe default. Contradictions between explicit values and the instance are errors.
func resolve(ctx context.Context, cfg Config, newReader func(context.Context) (instanceReader, error)) (*resolved, error) {
	if err := checkEnums(cfg); err != nil {
		return nil, err
	}
	if field := callerAuthField(cfg.ClientOption); field != "" && cfg.Auth.Mode != AuthAuto {
		return nil, fmt.Errorf("valkeygcp: ClientOption.%s conflicts with Auth.Mode", field)
	}
	r := &resolved{
		cfg:       cfg,
		topology:  cfg.Topology,
		auth:      cfg.Auth.Mode,
		tls:       cfg.TLS.Mode,
		discovery: cfg.DiscoveryEndpoint,
		primary:   cfg.PrimaryEndpoint,
		reader:    cfg.ReaderEndpoint,
	}
	var err error
	if cfg.Instance != "" {
		err = r.discover(ctx, newReader)
	} else {
		err = r.infer()
	}
	if err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// discover reads the instance and fills topology, modes, endpoints and the server CA.
func (r *resolved) discover(ctx context.Context, newReader func(context.Context) (instanceReader, error)) error {
	project, region, err := parseInstanceName(r.cfg.Instance)
	if err != nil {
		return err
	}
	rd, err := newReader(ctx)
	if err != nil {
		return err
	}
	defer rd.Close() // control plane is used for resolution only

	inst, err := rd.GetInstance(ctx, r.cfg.Instance)
	if err != nil {
		return controlPlaneError("read instance "+r.cfg.Instance, err)
	}
	topology, err := topologyOf(inst)
	if err != nil {
		return err
	}
	auth, err := authModeOf(inst)
	if err != nil {
		return err
	}
	tlsMode, err := tlsModeOf(inst)
	if err != nil {
		return err
	}

	// Explicit values must agree with the instance: fail here, not later at HELLO.
	if r.cfg.Topology != TopologyAuto && r.cfg.Topology != topology {
		return fmt.Errorf("valkeygcp: instance mode is %v but Topology is %v", inst.GetMode(), r.cfg.Topology)
	}
	if r.cfg.Auth.Mode != AuthAuto && r.cfg.Auth.Mode != auth {
		return fmt.Errorf("valkeygcp: instance uses %v but Auth.Mode is %v", inst.GetAuthorizationMode(), r.cfg.Auth.Mode)
	}
	if err := checkTLSMode(r.cfg, inst, tlsMode); err != nil {
		return err
	}
	r.topology, r.auth = topology, auth
	if r.tls != TLSCustomCA { // explicit TLSCustomCA = caller PEM for any server CA mode
		r.tls = tlsMode
	}

	eps := pscEndpoints(inst)
	hasInit := len(r.cfg.ClientOption.InitAddress) > 0
	switch topology {
	case TopologyCluster:
		if r.discovery == "" {
			r.discovery = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, r.cfg.Network)
		}
		if r.discovery == "" && !hasInit {
			return r.errMissing(memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY)
		}
	case TopologyClusterDisabled:
		if r.primary == "" {
			r.primary = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY, r.cfg.Network)
		}
		if r.reader == "" {
			r.reader = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_READER, r.cfg.Network)
		}
		if r.primary == "" && !hasInit {
			return r.errMissing(memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY)
		}
	}

	// Download the server CA only when it will be used.
	if r.cfg.ClientOption.TLSConfig != nil || hasCAMaterial(r.cfg.TLS) {
		return nil
	}
	switch r.tls {
	case TLSPerInstanceCA:
		r.caPEMs, err = rd.PerInstanceCA(ctx, r.cfg.Instance)
	case TLSSharedCA:
		r.caPEMs, err = rd.SharedRegionalCA(ctx, project, region)
	default: // TLSDisabled; TLSCustomCA without CA material is reported by validate
		return nil
	}
	if err != nil {
		return controlPlaneError("download the server CA for "+r.cfg.Instance, err)
	}
	if len(r.caPEMs) == 0 {
		return fmt.Errorf("valkeygcp: the Memorystore API returned no server CA certificate for %s", r.cfg.Instance)
	}
	return nil
}

// infer settles the Auto values without an instance, from the options that are set.
func (r *resolved) infer() error {
	if r.topology == TopologyAuto {
		switch {
		case r.discovery != "" && r.primary != "":
			return errors.New("valkeygcp: both DiscoveryEndpoint and PrimaryEndpoint are set; set Topology")
		case r.discovery != "":
			r.topology = TopologyCluster
		case r.primary != "":
			r.topology = TopologyClusterDisabled
		}
	}
	if r.auth == AuthAuto && callerAuthField(r.cfg.ClientOption) == "" {
		tok, iam := r.cfg.Auth.Token.hasSource(), r.cfg.Auth.IAM.hasIdentity()
		switch {
		case tok && iam:
			return errors.New("valkeygcp: both Auth.Token and Auth.IAM are configured; set Auth.Mode")
		case tok:
			r.auth = AuthToken
		case iam:
			r.auth = AuthIAM
		default:
			r.auth = AuthDisabled
		}
	}
	if r.tls == TLSAuto {
		r.tls = TLSDisabled
		if t := r.cfg.TLS; len(t.CAPEM) > 0 || t.CAFile != "" || t.Base != nil || t.ServerName != "" {
			r.tls = TLSCustomCA
		}
	}
	return nil
}

// validate checks the settled values before anything is dialed or created.
func (r *resolved) validate() error {
	hasInit := len(r.cfg.ClientOption.InitAddress) > 0
	switch r.topology {
	case TopologyCluster:
		if r.cfg.PrimaryEndpoint != "" || r.cfg.ReaderEndpoint != "" {
			return errors.New("valkeygcp: PrimaryEndpoint and ReaderEndpoint are for cluster-disabled instances, but the topology is cluster")
		}
		if r.discovery == "" && !hasInit {
			return errNoEndpoint
		}
	case TopologyClusterDisabled:
		if r.cfg.DiscoveryEndpoint != "" {
			return errors.New("valkeygcp: DiscoveryEndpoint is for cluster-mode instances, but the topology is cluster-disabled")
		}
		if r.primary == "" && !hasInit {
			return errNoEndpoint
		}
	default: // only ClientOption.InitAddress can stand in for an endpoint
		if r.reader != "" {
			return errors.New("valkeygcp: ReaderEndpoint needs PrimaryEndpoint")
		}
		if !hasInit {
			return errNoEndpoint
		}
	}
	callerAuth := callerAuthField(r.cfg.ClientOption) != ""
	if r.auth == AuthToken && !callerAuth && !r.cfg.Auth.Token.hasSource() {
		return errNoTokenSource
	}
	if r.tls != TLSDisabled && r.cfg.ClientOption.TLSConfig == nil && len(r.caPEMs) == 0 && !hasCAMaterial(r.cfg.TLS) {
		return errNeedsCA(r.tls)
	}
	return nil
}

func (r *resolved) errMissing(typ memorystorepb.ConnectionType) error {
	if r.cfg.Network != "" {
		return fmt.Errorf("valkeygcp: instance %s has no %v endpoint in network %q", r.cfg.Instance, typ, r.cfg.Network)
	}
	return fmt.Errorf("valkeygcp: instance %s has no %v endpoint yet (is its PSC connection created?)", r.cfg.Instance, typ)
}

func topologyOf(inst *memorystorepb.Instance) (Topology, error) {
	switch m := inst.GetMode(); m {
	case memorystorepb.Instance_CLUSTER, memorystorepb.Instance_MODE_UNSPECIFIED: // the API default is CLUSTER
		return TopologyCluster, nil
	case memorystorepb.Instance_CLUSTER_DISABLED:
		return TopologyClusterDisabled, nil
	default:
		if m.String() == "STANDALONE" { // deprecated name of CLUSTER_DISABLED
			return TopologyClusterDisabled, nil
		}
		return TopologyAuto, fmt.Errorf("valkeygcp: unsupported instance mode %v", m)
	}
}

func authModeOf(inst *memorystorepb.Instance) (AuthMode, error) {
	switch m := inst.GetAuthorizationMode(); m {
	case memorystorepb.Instance_AUTH_DISABLED, memorystorepb.Instance_AUTHORIZATION_MODE_UNSPECIFIED:
		return AuthDisabled, nil
	case memorystorepb.Instance_IAM_AUTH:
		return AuthIAM, nil
	case memorystorepb.Instance_TOKEN_AUTH:
		return AuthToken, nil
	default:
		return AuthAuto, fmt.Errorf("valkeygcp: unsupported authorization mode %v", m)
	}
}

func tlsModeOf(inst *memorystorepb.Instance) (TLSMode, error) {
	switch m := inst.GetTransitEncryptionMode(); m {
	case memorystorepb.Instance_TRANSIT_ENCRYPTION_DISABLED, memorystorepb.Instance_TRANSIT_ENCRYPTION_MODE_UNSPECIFIED:
		return TLSDisabled, nil
	case memorystorepb.Instance_SERVER_AUTHENTICATION:
		// TLS on: the server CA mode below picks the CA source.
	default:
		return TLSAuto, fmt.Errorf("valkeygcp: unsupported transit encryption mode %v", m)
	}
	switch m := inst.GetServerCaMode(); m {
	case memorystorepb.Instance_GOOGLE_MANAGED_PER_INSTANCE_CA, memorystorepb.Instance_SERVER_CA_MODE_UNSPECIFIED:
		return TLSPerInstanceCA, nil // unspecified: older instances predate CA modes
	case memorystorepb.Instance_GOOGLE_MANAGED_SHARED_CA:
		return TLSSharedCA, nil
	case memorystorepb.Instance_CUSTOMER_MANAGED_CAS_CA:
		return TLSCustomCA, nil
	default:
		return TLSAuto, fmt.Errorf("valkeygcp: unsupported server CA mode %v", m)
	}
}

// checkTLSMode reports an explicit TLS setting that contradicts the instance.
func checkTLSMode(cfg Config, inst *memorystorepb.Instance, discovered TLSMode) error {
	explicit := cfg.TLS.Mode
	switch {
	case discovered == TLSDisabled && cfg.ClientOption.TLSConfig != nil:
		return errors.New("valkeygcp: instance has in-transit encryption disabled, but ClientOption.TLSConfig is set")
	case explicit == TLSAuto || explicit == discovered:
		return nil
	case explicit == TLSCustomCA && discovered != TLSDisabled:
		return nil // caller-supplied CA bundle for a Google-managed CA
	}
	desc := inst.GetTransitEncryptionMode().String()
	if inst.GetTransitEncryptionMode() == memorystorepb.Instance_SERVER_AUTHENTICATION {
		desc += " with " + inst.GetServerCaMode().String()
	}
	return fmt.Errorf("valkeygcp: instance uses %s but TLS.Mode is %v", desc, explicit)
}

func checkEnums(cfg Config) error {
	if cfg.Auth.Mode < AuthAuto || cfg.Auth.Mode > AuthToken {
		return fmt.Errorf("valkeygcp: unknown Auth.Mode %v", cfg.Auth.Mode)
	}
	if cfg.TLS.Mode < TLSAuto || cfg.TLS.Mode > TLSCustomCA {
		return fmt.Errorf("valkeygcp: unknown TLS.Mode %v", cfg.TLS.Mode)
	}
	if cfg.Topology < TopologyAuto || cfg.Topology > TopologyClusterDisabled {
		return fmt.Errorf("valkeygcp: unknown Topology %v", cfg.Topology)
	}
	return nil
}

// controlPlaneError wraps a Memorystore API error, naming the permission when it is missing.
func controlPlaneError(action string, err error) error {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("valkeygcp: %s: needs memorystore.instances.get (roles/memorystore.viewer), or set explicit endpoints and modes without Instance: %w", action, err)
	}
	return fmt.Errorf("valkeygcp: %s: %w", action, err)
}
