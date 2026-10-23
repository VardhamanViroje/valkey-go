package valkeygcp

import (
	"context"
	"time"

	"github.com/valkey-io/valkey-go"
	"google.golang.org/api/option"
)

// Option configures what NewClient and ResolveClientOption add to a valkey.ClientOption:
// Memorystore discovery (WithInstance), IAM or Token Auth credentials (WithIAMOptions,
// WithDefaultIAM, WithTokenAuth), TLS from CA material (WithTLS) and the Google API clients
// used during setup (WithGoogleAPIOptions). Settings valkey-go already has a field for, such
// as addresses, TLSConfig and timeouts, are set on the valkey.ClientOption itself. Later
// options override earlier ones of the same kind.
type Option func(*config)

// config collects the Options of one NewClient or ResolveClientOption call.
type config struct {
	instance          string                // WithInstance
	network           string                // WithNetwork
	topology          Topology              // WithTopology
	iam               *IAMAuthOptions       // WithIAMOptions, WithDefaultIAM; nil when not given
	token             *TokenAuthOptions     // WithTokenAuth; nil when not given
	tls               TLSOptions            // WithTLS
	onAuth            func(AuthEvent)       // OnAuth
	onCredentialError func(error)           // OnCredentialError
	googleAPI         []option.ClientOption // WithGoogleAPIOptions
}

func newConfig(opts []Option) config {
	var c config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

// Connection defaults NewClient fills into the valkey.ClientOption fields left at zero.
const (
	defaultDialTimeout           = 2 * time.Second
	defaultKeepAlive             = 1 * time.Second
	defaultConnWriteTimeout      = 3 * time.Second
	defaultShardsRefreshInterval = 10 * time.Second // Fix C6: 10s with jitter
	// setupTimeout caps one-off setup calls (credential discovery, impersonation, the first
	// Token Auth read) when the caller's context has no earlier deadline.
	setupTimeout = 15 * time.Second
)

// NewClient returns a valkey.Client for Memorystore for Valkey. It takes the same
// valkey.ClientOption as valkey.NewClient: InitAddress holds the discovery endpoint (cluster
// mode) or the primary endpoint (cluster mode disabled), and Standalone.ReplicaAddress the
// reader endpoint, if any. NewClient fills the Memorystore defaults into the fields left at
// their zero value, adds what opts ask for, and connects.
//
// ctx bounds discovery, credential setup and connecting. valkey-go connects and
// authenticates while it builds the client, so setup needs working credentials; Memorystore
// IAM backend errors are retried with backoff until ctx ends (at most 15s when it has no
// earlier deadline). Token refreshes never use ctx.
func NewClient(ctx context.Context, option valkey.ClientOption, opts ...Option) (valkey.Client, error) {
	r, err := resolve(ctx, option, newConfig(opts), defaultInstanceReader) // §4.8
	if err != nil {
		return nil, err
	}
	opt, err := r.clientOption(ctx)
	if err != nil {
		return nil, err
	}
	return connect(ctx, opt, r.topology == TopologyCluster, r.authUser)
}

// ResolveClientOption returns the valkey.ClientOption NewClient would connect with, without
// connecting, for callers who build the client themselves (valkey.NewClient,
// valkeyotel.NewClient) or want to inspect it. Building the client that way skips NewClient's
// connect-time handling: the retries of Memorystore IAM backend errors during the handshake
// and the cluster mode check (see WithTopology).
func ResolveClientOption(ctx context.Context, option valkey.ClientOption, opts ...Option) (valkey.ClientOption, error) {
	r, err := resolve(ctx, option, newConfig(opts), defaultInstanceReader) // §4.8
	if err != nil {
		return valkey.ClientOption{}, err
	}
	return r.clientOption(ctx)
}

// sendReadsToReplicas routes read-only commands to the reader endpoint.
func sendReadsToReplicas(cmd valkey.Completed) bool {
	// Fix C5: Exclude blocking commands from replica routing
	return cmd.IsReadOnly() && !cmd.IsBlock()
}
