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
	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errNoEndpoint = errors.New("valkeygcp: no endpoint: set ClientOption.InitAddress, or use WithInstance")

// instanceReader is the part of the Memorystore API that discovery uses; tests replace it
// with a fake.
type instanceReader interface {
	GetInstance(ctx context.Context, name string) (*memorystorepb.Instance, error)
	PerInstanceCA(ctx context.Context, name string) ([]string, error)               // PEM certificates
	SharedRegionalCA(ctx context.Context, project, region string) ([]string, error) // PEM certificates
	Close() error
}

// googleAPI says how the Google API clients created during setup authenticate: as ts, the
// setup identity (nil for Application Default Credentials), then the caller's
// WithGoogleAPIOptions.
type googleAPI struct {
	ts   oauth2.TokenSource
	opts []option.ClientOption
}

// clientOptions returns the options for one Google API client.
func (g googleAPI) clientOptions() []option.ClientOption {
	all := make([]option.ClientOption, 0, len(g.opts)+1)
	if g.ts != nil {
		all = append(all, option.WithTokenSource(g.ts))
	}
	return append(all, g.opts...)
}

// readerFactory creates the instanceReader for one NewClient or ResolveClientOption call;
// tests replace it with a fake.
type readerFactory func(ctx context.Context, api googleAPI) (instanceReader, error)

// apiReader is the instanceReader backed by the Memorystore API.
type apiReader struct{ c *memorystore.Client }

// defaultInstanceReader reads the instance through the Memorystore API. The setup identity
// needs memorystore.instances.get.
func defaultInstanceReader(ctx context.Context, api googleAPI) (instanceReader, error) {
	c, err := memorystore.NewClient(ctx, api.clientOptions()...)
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
	// Keep every chain: during a CA rotation the old and the new CA are both listed, and a
	// node may present a certificate from either.
	var pems []string
	for _, chain := range ca.GetManagedServerCa().GetCaCerts() {
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

// pscEndpoint is one Private Service Connect (PSC) endpoint of the instance.
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
	for _, d := range inst.GetDiscoveryEndpoints() { //nolint:staticcheck // SA1019: same fallback (golangci-lint ignores lint:ignore)
		add(d.GetAddress(), d.GetPort(), memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, d.GetNetwork())
	}
	return out
}

// pickEndpoint returns the address of the first endpoint of type typ in network, or ""
// when there is none. An empty network, on either side, matches any network.
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

// trimNetworkURL drops what comes before "projects/" in a network URL.
func trimNetworkURL(n string) string {
	if i := strings.Index(n, "projects/"); i >= 0 {
		return n[i:]
	}
	return n
}

// resolve settles every setting. The order of precedence is: what the caller set on the
// ClientOption and in Options, then what the instance says (WithInstance), then a safe
// default. A caller setting that contradicts the instance is an error.
func resolve(ctx context.Context, option valkey.ClientOption, cfg config, newReader readerFactory) (*resolved, error) {
	if err := checkEnums(cfg); err != nil {
		return nil, err
	}
	if field := callerAuthField(option); field != "" && (cfg.iam != nil || cfg.token != nil) {
		return nil, fmt.Errorf("valkeygcp: ClientOption.%s conflicts with %s", field, authOptionName(cfg))
	}
	if cfg.network != "" && cfg.instance == "" {
		return nil, errors.New("valkeygcp: WithNetwork needs WithInstance")
	}
	if len(cfg.googleAPI) > 0 && cfg.instance == "" {
		return nil, errors.New("valkeygcp: WithGoogleAPIOptions needs WithInstance")
	}
	r := &resolved{
		opt:      option,
		cfg:      cfg,
		topology: cfg.topology,
		tls:      cfg.tls.Mode,
	}
	var err error
	if cfg.instance != "" {
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

// authOptionName names the auth option set in cfg, for error messages.
func authOptionName(cfg config) string {
	switch {
	case cfg.iam != nil && cfg.token != nil:
		return "WithIAMOptions and WithTokenAuth"
	case cfg.iam != nil:
		return "WithIAMOptions"
	}
	return "WithTokenAuth"
}

// setupIdentity picks the identity of the Google API calls made during setup: the one
// WithIAMOptions names (see IAMAuthOptions), built once here and reused by the IAM token
// provider, or Application Default Credentials without WithIAMOptions. The caller's
// WithGoogleAPIOptions follow it.
func (r *resolved) setupIdentity(ctx context.Context) error {
	r.api.opts = r.cfg.googleAPI
	if r.cfg.iam == nil {
		return nil
	}
	iam, err := withIAMDefaults(*r.cfg.iam)
	if err != nil {
		return err
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	base, err := setupBaseCreds(setupCtx, iam)
	if err != nil {
		return err
	}
	r.iamBase = &base
	r.api.ts = oauth2.ReuseTokenSource(nil, base.source) // one token for every setup call
	return nil
}

// discover reads the instance and fills topology, modes, endpoints and the server CA.
func (r *resolved) discover(ctx context.Context, newReader readerFactory) error {
	project, region, err := parseInstanceName(r.cfg.instance)
	if err != nil {
		return err
	}
	if err := r.setupIdentity(ctx); err != nil {
		return err
	}
	rd, err := newReader(ctx, r.api)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }() // the Memorystore API is only used during setup

	inst, err := rd.GetInstance(ctx, r.cfg.instance)
	if err != nil {
		return controlPlaneError("read instance "+r.cfg.instance, err)
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
	if r.cfg.topology != TopologyAuto && r.cfg.topology != topology {
		return fmt.Errorf("valkeygcp: instance mode is %v but WithTopology is %v", inst.GetMode(), r.cfg.topology)
	}
	if err := checkTLSMode(r.opt, r.cfg.tls, inst, tlsMode); err != nil {
		return err
	}
	r.topology, r.auth = topology, auth
	if r.tls != TLSCustomCA { // explicit TLSCustomCA = caller PEM for any server CA mode
		r.tls = tlsMode
	}

	eps := pscEndpoints(inst)
	hasInit := len(r.opt.InitAddress) > 0
	switch topology {
	case TopologyCluster:
		r.discovery = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY, r.cfg.network)
		if r.discovery == "" && !hasInit {
			return r.errMissing(memorystorepb.ConnectionType_CONNECTION_TYPE_DISCOVERY)
		}
	case TopologyClusterDisabled:
		r.primary = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY, r.cfg.network)
		r.reader = pickEndpoint(eps, memorystorepb.ConnectionType_CONNECTION_TYPE_READER, r.cfg.network)
		if r.primary == "" && !hasInit {
			return r.errMissing(memorystorepb.ConnectionType_CONNECTION_TYPE_PRIMARY)
		}
	}

	// Download the server CA only when it will be used.
	if r.opt.TLSConfig != nil || hasCAMaterial(r.cfg.tls) {
		return nil
	}
	if r.tls == TLSCustomCA {
		return r.fetchCustomCA(ctx, inst)
	}
	switch r.tls {
	case TLSPerInstanceCA:
		r.caPEMs, err = rd.PerInstanceCA(ctx, r.cfg.instance)
	case TLSSharedCA:
		r.caPEMs, err = rd.SharedRegionalCA(ctx, project, region)
	default: // TLSDisabled
		return nil
	}
	if err != nil {
		return controlPlaneError("download the server CA for "+r.cfg.instance, err)
	}
	if len(r.caPEMs) == 0 {
		return fmt.Errorf("valkeygcp: the Memorystore API returned no server CA certificate for %s", r.cfg.instance)
	}
	return nil
}

// fetchCustomCA gets the server CA of a CUSTOMER_MANAGED_CAS_CA instance from its CA
// Service pool through TLSOptions.FetchCustomCA, because the Memorystore API can't return
// it. Without FetchCustomCA, validate reports the missing CA.
func (r *resolved) fetchCustomCA(ctx context.Context, inst *memorystorepb.Instance) error {
	fetch := r.cfg.tls.FetchCustomCA
	if fetch == nil || inst.GetServerCaMode() != memorystorepb.Instance_CUSTOMER_MANAGED_CAS_CA {
		return nil
	}
	pool := inst.GetServerCaPool()
	if pool == "" {
		return fmt.Errorf("valkeygcp: instance %s uses CUSTOMER_MANAGED_CAS_CA but reports no server_ca_pool", r.cfg.instance)
	}
	pems, err := fetch(ctx, pool, r.api.clientOptions()...) // same identity as the instance lookup
	if err != nil {
		return fmt.Errorf("valkeygcp: fetch the CA certificates of %s (needs privateca.caPools.get, for example roles/privateca.poolReader): %w", pool, err)
	}
	if len(pems) == 0 {
		return fmt.Errorf("valkeygcp: CA pool %s returned no CA certificate", pool)
	}
	r.caPEMs = pems
	return nil
}

// infer settles the Auto values without an instance, from the options that are set. The
// topology stays TopologyAuto unless WithTopology sets it: valkey-go detects it when it
// connects.
func (r *resolved) infer() error {
	switch {
	case r.cfg.iam != nil && r.cfg.token != nil:
		return errors.New("valkeygcp: both WithIAMOptions and WithTokenAuth are set; without WithInstance, pass only one")
	case r.cfg.iam != nil:
		r.auth = authIAM
	case r.cfg.token != nil:
		r.auth = authToken
	default:
		r.auth = authDisabled
	}
	if r.tls == TLSAuto {
		r.tls = TLSDisabled
		if t := r.cfg.tls; len(t.CAPEM) > 0 || t.CAFile != "" || t.Base != nil || t.ServerName != "" {
			r.tls = TLSCustomCA
		}
	}
	return nil
}

// validate checks the settled values before anything is dialed or created.
func (r *resolved) validate() error {
	hasInit := len(r.opt.InitAddress) > 0
	switch r.topology {
	case TopologyCluster:
		if len(r.opt.Standalone.ReplicaAddress) > 0 {
			return errors.New("valkeygcp: ClientOption.Standalone.ReplicaAddress is for cluster-disabled instances, but the topology is cluster")
		}
		if r.discovery == "" && !hasInit {
			return errNoEndpoint
		}
	case TopologyClusterDisabled:
		if r.primary == "" && !hasInit {
			return errNoEndpoint
		}
	default: // no instance: only ClientOption.InitAddress can name the endpoint
		if !hasInit {
			return errNoEndpoint
		}
	}
	callerAuth := callerAuthField(r.opt) != ""
	if r.auth == authToken && !callerAuth && (r.cfg.token == nil || !r.cfg.token.hasSource()) {
		return errNoTokenSource
	}
	if r.tls != TLSDisabled && r.opt.TLSConfig == nil && len(r.caPEMs) == 0 && !hasCAMaterial(r.cfg.tls) {
		return errNeedsCA(r.tls)
	}
	return r.checkPlaintextCredentials(callerAuth)
}

// checkPlaintextCredentials refuses to send IAM or Token Auth credentials without TLS when
// there is no instance, unless the caller turned TLS off on purpose. Without an instance,
// TLSAuto becomes TLSDisabled when no CA option is set, and the AUTH command would then
// cross the network in plaintext, even to an instance that only accepts TLS. With
// WithInstance, the instance's in-transit encryption setting decides.
func (r *resolved) checkPlaintextCredentials(callerAuth bool) error {
	if r.cfg.instance != "" || callerAuth || r.tls != TLSDisabled || r.cfg.tls.Mode == TLSDisabled || r.opt.TLSConfig != nil {
		return nil
	}
	var what string
	switch r.auth {
	case authIAM:
		what = "IAM access tokens"
	case authToken:
		what = "Token Auth tokens"
	default:
		return nil
	}
	return fmt.Errorf("valkeygcp: refusing to send %s without TLS: pass WithTLS with the instance's server CA (TLSOptions.CAFile or CAPEM) or set ClientOption.TLSConfig, or pass WithTLS(TLSOptions{Mode: TLSDisabled}) if the instance has in-transit encryption disabled", what)
}

// errMissing reports that the instance has no endpoint of type typ.
func (r *resolved) errMissing(typ memorystorepb.ConnectionType) error {
	if r.cfg.network != "" {
		return fmt.Errorf("valkeygcp: instance %s has no %v endpoint in network %q", r.cfg.instance, typ, r.cfg.network)
	}
	return fmt.Errorf("valkeygcp: instance %s has no %v endpoint yet (is its PSC connection created?)", r.cfg.instance, typ)
}

// topologyOf maps the instance's mode to a Topology.
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

// authModeOf maps the instance's authorization mode to an authMode.
func authModeOf(inst *memorystorepb.Instance) (authMode, error) {
	switch m := inst.GetAuthorizationMode(); m {
	case memorystorepb.Instance_AUTH_DISABLED, memorystorepb.Instance_AUTHORIZATION_MODE_UNSPECIFIED:
		return authDisabled, nil
	case memorystorepb.Instance_IAM_AUTH:
		return authIAM, nil
	case memorystorepb.Instance_TOKEN_AUTH:
		return authToken, nil
	default:
		return authAuto, fmt.Errorf("valkeygcp: unsupported authorization mode %v", m)
	}
}

// tlsModeOf maps the instance's transit encryption mode and server CA mode to a TLSMode.
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

// checkTLSMode reports a caller TLS setting that contradicts the instance.
func checkTLSMode(opt valkey.ClientOption, t TLSOptions, inst *memorystorepb.Instance, discovered TLSMode) error {
	explicit := t.Mode
	switch {
	case discovered == TLSDisabled && opt.TLSConfig != nil:
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
	return fmt.Errorf("valkeygcp: instance uses %s but WithTLS sets Mode %v", desc, explicit)
}

// checkEnums rejects TLSMode and Topology values that aren't one of the defined constants.
func checkEnums(cfg config) error {
	if cfg.tls.Mode < TLSAuto || cfg.tls.Mode > TLSCustomCA {
		return fmt.Errorf("valkeygcp: unknown TLSOptions.Mode %v", cfg.tls.Mode)
	}
	if cfg.topology < TopologyAuto || cfg.topology > TopologyClusterDisabled {
		return fmt.Errorf("valkeygcp: unknown Topology %v", cfg.topology)
	}
	return nil
}

// controlPlaneError wraps a Memorystore API error, naming the permission when it is missing.
func controlPlaneError(action string, err error) error {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("valkeygcp: %s: needs memorystore.instances.get (roles/memorystore.viewer), or connect without WithInstance: set ClientOption.InitAddress and the auth and TLS options yourself: %w", action, err)
	}
	return fmt.Errorf("valkeygcp: %s: %w", action, err)
}
