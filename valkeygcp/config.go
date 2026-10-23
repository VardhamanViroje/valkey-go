package valkeygcp

import (
	"context"
	"crypto/tls"
	"strconv"

	"github.com/valkey-io/valkey-go"
	"google.golang.org/api/option"
)

// authMode mirrors memorystore.v1.Instance.AuthorizationMode.
type authMode int

const (
	authAuto     authMode = iota // not settled yet
	authDisabled                 // AUTH_DISABLED
	authIAM                      // IAM_AUTH
	authToken                    // TOKEN_AUTH
)

// TLSMode mirrors transit_encryption_mode + server_ca_mode.
type TLSMode int

// TLSMode values. Each mode except TLSAuto matches a transit encryption and server CA mode.
const (
	// TLSAuto takes the mode from the instance with WithInstance. Otherwise it is
	// TLSCustomCA when TLS options are set (CAPEM, CAFile, Base or ServerName), else TLSDisabled.
	TLSAuto          TLSMode = iota
	TLSDisabled              // TRANSIT_ENCRYPTION_DISABLED
	TLSPerInstanceCA         // SERVER_AUTHENTICATION + GOOGLE_MANAGED_PER_INSTANCE_CA
	TLSSharedCA              // SERVER_AUTHENTICATION + GOOGLE_MANAGED_SHARED_CA
	TLSCustomCA              // SERVER_AUTHENTICATION + CUSTOMER_MANAGED_CAS_CA, or any caller PEM
)

func (m TLSMode) String() string {
	switch m {
	case TLSAuto:
		return "TLSAuto"
	case TLSDisabled:
		return "TLSDisabled"
	case TLSPerInstanceCA:
		return "TLSPerInstanceCA"
	case TLSSharedCA:
		return "TLSSharedCA"
	case TLSCustomCA:
		return "TLSCustomCA"
	}
	return "TLSMode(" + strconv.Itoa(int(m)) + ")"
}

// Topology mirrors memorystore.v1.Instance.Mode.
type Topology int

// Topology values. Each topology except TopologyAuto matches one Instance.Mode.
const (
	// TopologyAuto takes the topology from the instance with WithInstance; otherwise
	// valkey-go detects it when it connects.
	TopologyAuto            Topology = iota
	TopologyCluster                  // CLUSTER: InitAddress is the discovery endpoint
	TopologyClusterDisabled          // CLUSTER_DISABLED: InitAddress is the primary endpoint
)

func (t Topology) String() string {
	switch t {
	case TopologyAuto:
		return "TopologyAuto"
	case TopologyCluster:
		return "TopologyCluster"
	case TopologyClusterDisabled:
		return "TopologyClusterDisabled"
	}
	return "Topology(" + strconv.Itoa(int(t)) + ")"
}

// TLSOptions configures in-transit encryption (WithTLS).
type TLSOptions struct {
	Mode       TLSMode
	CAPEM      []byte      // TLSCustomCA, or an offline bundle for any mode
	CAFile     string      // alternative to CAPEM
	ServerName string      // optional verification override
	Base       *tls.Config // optional base (cloned, never mutated)
	// FetchCustomCA fetches the server CA certificates (PEM) of a CUSTOMER_MANAGED_CAS_CA
	// instance from its Certificate Authority Service pool, which the Memorystore API can't
	// return (U11). NewClient calls it with the instance's server_ca_pool when WithInstance
	// is used and no CA material is set, and with opts for the CA Service client: the setup
	// identity (see IAMAuthOptions) followed by WithGoogleAPIOptions. cas.FetchPoolCAs, in
	// package github.com/valkey-io/valkey-go/valkeygcp/cas, implements it.
	FetchCustomCA func(ctx context.Context, caPool string, opts ...option.ClientOption) ([]string, error)
}

// WithInstance makes NewClient read the instance "projects/P/locations/R/instances/I"
// (memorystore.instances.get, roles/memorystore.viewer) and take from it what the
// valkey.ClientOption leaves empty: the endpoint (InitAddress), the reader endpoint of a
// cluster-disabled instance (Standalone.ReplicaAddress) and the server CA (TLSConfig). The
// instance's cluster mode, auth mode and TLS mode are used too: the auth mode decides which of
// WithIAMOptions and WithTokenAuth is used, so one call can carry both for different
// environments, and an IAM_AUTH instance uses Application Default Credentials when
// WithIAMOptions isn't given. The Memorystore API is only used while NewClient runs.
func WithInstance(name string) Option {
	return func(c *config) { c.instance = name }
}

// WithNetwork selects the PSC endpoint group of one VPC network ("projects/P/global/networks/N",
// or just N) when the instance is reachable from several networks. It needs WithInstance.
func WithNetwork(network string) Option {
	return func(c *config) { c.network = network }
}

// WithGoogleAPIOptions adds options for the Google API clients NewClient creates during
// setup: the Memorystore API client of WithInstance and the CA Service client of
// TLSOptions.FetchCustomCA. They follow the setup identity (see IAMAuthOptions), so they can
// replace its credentials, or add an endpoint, quota project or universe domain. Each call
// adds to the options of earlier calls. It needs WithInstance.
func WithGoogleAPIOptions(opts ...option.ClientOption) Option {
	return func(c *config) { c.googleAPI = append(c.googleAPI, opts...) }
}

// WithTopology states the instance's cluster mode. With WithInstance it must match the
// instance. TopologyCluster makes NewClient fail instead of returning a single-node client
// when valkey-go can't use cluster mode (U7), for example because an ACL rule doesn't allow
// CLUSTER SHARDS; WithInstance does the same for cluster-mode instances.
// TopologyClusterDisabled leaves out the cluster defaults.
func WithTopology(t Topology) Option {
	return func(c *config) { c.topology = t }
}

// OnAuth receives an AuthEvent each time credentials are handed to valkey-go: on every new
// connection and at every proactive re-AUTH (U9). It must return quickly. It is used for IAM
// and Token Auth when IAMAuthOptions.OnAuth or TokenAuthOptions.OnAuth is nil.
func OnAuth(fn func(AuthEvent)) Option {
	return func(c *config) { c.onAuth = fn }
}

// OnCredentialError receives token and secret fetch errors absorbed by the last-known-good
// logic (U6), for logs and metrics. It is used for IAM and Token Auth when
// IAMAuthOptions.OnCredentialError or TokenAuthOptions.OnCredentialError is nil.
func OnCredentialError(fn func(error)) Option {
	return func(c *config) { c.onCredentialError = fn }
}

// hasSource reports whether a Token Auth token source is set.
func (o TokenAuthOptions) hasSource() bool {
	return o.Source != nil || o.SecretVersion != "" || o.Token != ""
}

// hasCAMaterial reports whether the caller supplied CA certificates.
func hasCAMaterial(o TLSOptions) bool {
	return len(o.CAPEM) > 0 || o.CAFile != "" || (o.Base != nil && o.Base.RootCAs != nil)
}

// callerAuthField names the ClientOption credential field the caller set, if any.
// Caller-managed credentials are used as is; an auth option next to them is an error.
func callerAuthField(o valkey.ClientOption) string {
	switch {
	case o.AuthCredentialsFn != nil:
		return "AuthCredentialsFn"
	case o.Password != "":
		return "Password"
	}
	return ""
}

// resolved is the caller's ClientOption and Options with every Auto value and instance
// endpoint settled by resolve.
type resolved struct {
	opt       valkey.ClientOption // the caller's option; clientOption fills its zero fields
	cfg       config
	topology  Topology // TopologyAuto when neither the instance nor WithTopology tells
	auth      authMode
	tls       TLSMode
	discovery string    // discovery endpoint read from a cluster-mode instance
	primary   string    // primary endpoint read from a cluster-disabled instance
	reader    string    // reader endpoint read from a cluster-disabled instance, if any
	caPEMs    []string  // server CA certificates downloaded from the Memorystore API
	authUser  string    // AUTH username wired by clientOption, for error messages
	api       googleAPI // how the setup API calls authenticate (setupIdentity)
	// iamBase holds the upstream credentials of WithIAMOptions when resolve built them for
	// the instance lookup; the IAM token provider reuses them.
	iamBase *baseCreds
}

// iamProvider builds the IAM token provider from WithIAMOptions, or from Application Default
// Credentials for an IAM_AUTH instance without it, reusing the credentials built for the
// instance lookup.
func (r *resolved) iamProvider(ctx context.Context) (*tokenProvider, error) {
	var iam IAMAuthOptions
	if r.cfg.iam != nil {
		iam = *r.cfg.iam
	}
	if iam.OnCredentialError == nil {
		iam.OnCredentialError = r.cfg.onCredentialError
	}
	if iam.OnAuth == nil {
		iam.OnAuth = r.cfg.onAuth
	}
	iam, err := withIAMDefaults(iam)
	if err != nil {
		return nil, err
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	if r.iamBase == nil {
		base, err := setupBaseCreds(setupCtx, iam)
		if err != nil {
			return nil, err
		}
		r.iamBase = &base
	}
	return newTokenProvider(setupCtx, iam, *r.iamBase)
}

// clientOption builds the valkey.ClientOption, filling only zero-valued fields of the
// caller's option (§4.7).
func (r *resolved) clientOption(ctx context.Context) (valkey.ClientOption, error) {
	opt := r.opt
	if len(opt.InitAddress) == 0 { // validate let this through only with an instance endpoint
		switch r.topology {
		case TopologyCluster:
			opt.InitAddress = []string{r.discovery}
		case TopologyClusterDisabled:
			opt.InitAddress = []string{r.primary}
		}
	}
	// The reader endpoint can't be combined with EnableRedirect (valkey.NewClient rejects it).
	if r.reader != "" && len(opt.Standalone.ReplicaAddress) == 0 && !opt.Standalone.EnableRedirect {
		opt.Standalone.ReplicaAddress = []string{r.reader}
	}
	if len(opt.Standalone.ReplicaAddress) > 0 {
		if opt.SendToReplicas == nil {
			opt.SendToReplicas = sendReadsToReplicas
		}
	} else if r.topology != TopologyClusterDisabled {
		// Cluster mode, or not known before connecting. valkey-go reads these only in its
		// cluster client, so they are harmless when it falls back to a single-node client.
		// A false bool can't be told apart from an unset one, so the bools are always on.
		opt.ClusterOption.PreferInitAddressRefresh = true // topology only through InitAddress
		opt.ClusterOption.PreferClusterShards = true
		if opt.ClusterOption.ShardsRefreshInterval == 0 {
			opt.ClusterOption.ShardsRefreshInterval = defaultShardsRefreshInterval
		}
	}
	if opt.Dialer.Timeout == 0 {
		opt.Dialer.Timeout = defaultDialTimeout
	}
	if opt.Dialer.KeepAlive == 0 {
		opt.Dialer.KeepAlive = defaultKeepAlive
	}
	if opt.ConnWriteTimeout == 0 {
		opt.ConnWriteTimeout = defaultConnWriteTimeout
	}
	if opt.RetryDelay == nil {
		opt.RetryDelay = memorystoreRetryDelay
	}

	// TLS before auth: it can fail, and the auth providers may hold resources.
	if opt.TLSConfig == nil {
		cfg, err := buildTLSConfig(r.cfg.tls, r.tls, r.caPEMs)
		if err != nil {
			return valkey.ClientOption{}, err
		}
		opt.TLSConfig = cfg
	}

	if opt.AuthCredentialsFn == nil && opt.Password == "" {
		plaintext := opt.TLSConfig == nil // reported in AuthEvent.Plaintext (U10)
		switch r.auth {
		case authIAM:
			p, err := r.iamProvider(ctx)
			if err != nil {
				return valkey.ClientOption{}, err
			}
			p.plaintext, r.authUser = plaintext, p.username
			opt.AuthCredentialsFn = p.AuthCredentialsFn()
			installDialGate(&opt) // U8: space out re-dials after ERR_IAM_*
		case authToken:
			tok := *r.cfg.token // validate checked that WithTokenAuth set a source
			if tok.OnCredentialError == nil {
				tok.OnCredentialError = r.cfg.onCredentialError
			}
			if tok.OnAuth == nil {
				tok.OnAuth = r.cfg.onAuth
			}
			p, err := newTokenAuthProvider(ctx, tok)
			if err != nil {
				return valkey.ClientOption{}, err
			}
			p.plaintext, r.authUser = plaintext, tok.Username
			if r.authUser == "" {
				r.authUser = defaultUser
			}
			opt.AuthCredentialsFn = p.AuthCredentialsFn()
		}
	}
	return opt, nil
}
