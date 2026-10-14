package valkeygcp

import (
	"context"
	"crypto/tls"
	"strconv"

	"github.com/valkey-io/valkey-go"
)

// AuthMode mirrors memorystore.v1.Instance.AuthorizationMode.
type AuthMode int

const (
	// AuthAuto takes the mode from the instance when Config.Instance is set. Otherwise it is
	// inferred from the options: AuthToken when a token source is set, AuthIAM when an IAM
	// identity option is set, AuthDisabled when neither is.
	AuthAuto     AuthMode = iota
	AuthDisabled          // AUTH_DISABLED
	AuthIAM               // IAM_AUTH
	AuthToken             // TOKEN_AUTH
)

func (m AuthMode) String() string {
	switch m {
	case AuthAuto:
		return "AuthAuto"
	case AuthDisabled:
		return "AuthDisabled"
	case AuthIAM:
		return "AuthIAM"
	case AuthToken:
		return "AuthToken"
	}
	return "AuthMode(" + strconv.Itoa(int(m)) + ")"
}

// TLSMode mirrors transit_encryption_mode + server_ca_mode.
type TLSMode int

const (
	// TLSAuto takes the mode from the instance when Config.Instance is set. Otherwise it is
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

const (
	// TopologyAuto takes the topology from the instance when Config.Instance is set,
	// otherwise from the endpoint that is set.
	TopologyAuto            Topology = iota
	TopologyCluster                  // CLUSTER: discovery endpoint
	TopologyClusterDisabled          // CLUSTER_DISABLED: primary (+ reader) endpoint
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

// Config is the single top-level entry point for every GCP auth mechanism.
type Config struct {
	// Instance is "projects/P/locations/R/instances/I". When set, NewClient reads the
	// instance (memorystore.instances.get) and fills every *Auto field and endpoint.
	// The instance's auth mode then decides which of Auth.IAM / Auth.Token is used, so one
	// Config can carry both for different environments.
	Instance string
	// Network selects the PSC endpoint group when the instance is reachable from several
	// VPCs ("projects/P/global/networks/N", or just N). Optional.
	Network string

	// Explicit endpoints: no control-plane call needed. With Instance set they override the
	// discovered endpoints.
	DiscoveryEndpoint string // cluster mode
	PrimaryEndpoint   string // cluster-disabled
	ReaderEndpoint    string // cluster-disabled, optional
	Topology          Topology

	Auth AuthOptions
	TLS  TLSOptions

	// ClientOption is copied first; valkeygcp only fills fields left at their zero value.
	// Credentials set here (AuthCredentialsFn or Password) or a TLSConfig are used as is.
	ClientOption valkey.ClientOption
}

// AuthOptions selects and configures the authentication mechanism.
type AuthOptions struct {
	Mode  AuthMode
	IAM   IAMAuthOptions   // IAM_AUTH
	Token TokenAuthOptions // TOKEN_AUTH
	// OnCredentialError receives token/secret fetch errors absorbed by the
	// last-known-good logic (U6), for logs and metrics.
	OnCredentialError func(error)
}

// TLSOptions configures in-transit encryption.
type TLSOptions struct {
	Mode       TLSMode
	CAPEM      []byte      // TLSCustomCA, or an offline bundle for any mode
	CAFile     string      // alternative to CAPEM
	ServerName string      // optional verification override
	Base       *tls.Config // optional base (cloned, never mutated)
}

// hasSource reports whether a Token Auth token source is set.
func (o TokenAuthOptions) hasSource() bool {
	return o.Source != nil || o.SecretVersion != "" || o.Token != ""
}

// hasIdentity reports whether an IAM identity option is set (AuthAuto inference). Tuning
// knobs such as RefreshBuffer or Scopes don't count: plain ADC needs Auth.Mode = AuthIAM.
func (o IAMAuthOptions) hasIdentity() bool {
	return o.CustomTokenSource != nil || len(o.CredentialsJSON) > 0 || o.ImpersonateSA != "" ||
		o.Username != "" || o.UsernameStrategy != UsernameDefault
}

// hasCAMaterial reports whether the caller supplied CA certificates.
func hasCAMaterial(o TLSOptions) bool {
	return len(o.CAPEM) > 0 || o.CAFile != "" || (o.Base != nil && o.Base.RootCAs != nil)
}

// callerAuthField names the ClientOption credential field the caller set, if any.
// Caller-managed credentials are used as is (with AuthAuto) or rejected (with Auth.Mode).
func callerAuthField(o valkey.ClientOption) string {
	switch {
	case o.AuthCredentialsFn != nil:
		return "AuthCredentialsFn"
	case o.Password != "":
		return "Password"
	}
	return ""
}

// NewClient resolves cfg (§1.5) and returns a ready valkey.Client.
func NewClient(ctx context.Context, cfg Config) (valkey.Client, error) {
	r, err := resolve(ctx, cfg, defaultInstanceReader) // §4.8
	if err != nil {
		return nil, err
	}
	opt, err := r.clientOption(ctx)
	if err != nil {
		return nil, err
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		r.close() // release the Secret Manager client created for TOKEN_AUTH
		return nil, err
	}
	return client, nil
}

// ResolveClientOption returns the fully wired valkey.ClientOption without dialing,
// for callers who want to inspect or adjust it before valkey.NewClient.
func ResolveClientOption(ctx context.Context, cfg Config) (valkey.ClientOption, error) {
	r, err := resolve(ctx, cfg, defaultInstanceReader) // §4.8
	if err != nil {
		return valkey.ClientOption{}, err
	}
	return r.clientOption(ctx)
}

// resolved is a Config with every Auto value and endpoint settled by resolve.
type resolved struct {
	cfg       Config
	topology  Topology // TopologyAuto only when the caller supplied ClientOption.InitAddress
	auth      AuthMode
	tls       TLSMode
	discovery string
	primary   string
	reader    string
	caPEMs    []string // server CA certificates downloaded from the Memorystore API
	closers   []func()
}

// close releases resources created by clientOption.
func (r *resolved) close() {
	for _, c := range r.closers {
		c()
	}
	r.closers = nil
}

// clientOption builds the valkey.ClientOption, filling only zero-valued fields of
// cfg.ClientOption (§4.7).
func (r *resolved) clientOption(ctx context.Context) (valkey.ClientOption, error) {
	opt := r.cfg.ClientOption
	switch r.topology {
	case TopologyCluster:
		if len(opt.InitAddress) == 0 {
			opt.InitAddress = []string{r.discovery}
		}
		// Same defaults as NewClusterClient.
		opt.ClusterOption.PreferInitAddressRefresh = true
		opt.ClusterOption.PreferClusterShards = true
		if opt.ClusterOption.ShardsRefreshInterval == 0 {
			opt.ClusterOption.ShardsRefreshInterval = defaultShardsRefreshInterval
		}
	case TopologyClusterDisabled:
		if len(opt.InitAddress) == 0 {
			opt.InitAddress = []string{r.primary}
		}
		// The reader endpoint can't be combined with EnableRedirect (valkey.NewClient rejects it).
		if r.reader != "" && len(opt.Standalone.ReplicaAddress) == 0 && !opt.Standalone.EnableRedirect {
			opt.Standalone.ReplicaAddress = []string{r.reader}
		}
		if len(opt.Standalone.ReplicaAddress) > 0 && opt.SendToReplicas == nil {
			opt.SendToReplicas = sendReadsToReplicas
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
		cfg, err := buildTLSConfig(r.cfg.TLS, r.tls, r.caPEMs)
		if err != nil {
			return valkey.ClientOption{}, err
		}
		opt.TLSConfig = cfg
	}

	if opt.AuthCredentialsFn == nil && opt.Password == "" {
		switch r.auth {
		case AuthIAM:
			iam := r.cfg.Auth.IAM
			if iam.OnCredentialError == nil {
				iam.OnCredentialError = r.cfg.Auth.OnCredentialError
			}
			p, err := NewGCPTokenProvider(ctx, iam)
			if err != nil {
				return valkey.ClientOption{}, err
			}
			opt.AuthCredentialsFn = p.AuthCredentialsFn()
		case AuthToken:
			p, err := newTokenAuthProvider(ctx, r.cfg.Auth.Token, r.cfg.Auth.OnCredentialError)
			if err != nil {
				return valkey.ClientOption{}, err
			}
			r.closers = append(r.closers, p.close)
			opt.AuthCredentialsFn = p.AuthCredentialsFn()
		}
	}
	return opt, nil
}
