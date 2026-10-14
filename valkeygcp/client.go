package valkeygcp

import (
	"context"
	"net"
	"time"

	"github.com/valkey-io/valkey-go"
)

// GCPOption configures the valkey.ClientOption built by NewClusterClient and
// NewStandaloneClient. ctx is the constructor's context: options that call Google APIs while
// the client is set up (credential discovery, impersonation, the first Token Auth read) stop
// when it is cancelled or its deadline passes. Token refreshes never use it, because they run
// for the life of the client.
type GCPOption func(ctx context.Context, opt *valkey.ClientOption) error

// Connection defaults shared by the constructors and NewClient.
const (
	defaultDialTimeout           = 2 * time.Second
	defaultKeepAlive             = 1 * time.Second
	defaultConnWriteTimeout      = 3 * time.Second
	defaultShardsRefreshInterval = 10 * time.Second // Fix C6: 10s with jitter
	// setupTimeout caps one-off setup calls (credential discovery, impersonation, the first
	// Token Auth read) when the caller's context has no earlier deadline.
	setupTimeout = 15 * time.Second
)

// NewClusterClient creates a Memorystore Cluster Mode client with discovery pinning,
// fast failover reconnection, and optional IAM authentication.
//
// ctx bounds the setup done by opts (see GCPOption). valkey-go connects and authenticates
// while it builds the client, so setup needs working credentials.
func NewClusterClient(ctx context.Context, discoveryEndpoint string, opts ...GCPOption) (valkey.Client, error) {
	clientOpt := valkey.ClientOption{
		InitAddress: []string{discoveryEndpoint},
		ClusterOption: valkey.ClusterOption{
			PreferInitAddressRefresh: true,
			ShardsRefreshInterval:    defaultShardsRefreshInterval,
			PreferClusterShards:      true,
		},
		Dialer: net.Dialer{
			KeepAlive: defaultKeepAlive,
			Timeout:   defaultDialTimeout,
		},
		ConnWriteTimeout: defaultConnWriteTimeout,
		RetryDelay:       memorystoreRetryDelay, // Correction V9: defined in retry.go
	}
	return newClient(ctx, clientOpt, opts)
}

// NewStandaloneClient creates a Memorystore Standalone (Cluster Disabled) client with
// automatic read/write splitting between Primary and Reader Endpoints.
//
// ctx bounds the setup done by opts (see GCPOption). valkey-go connects and authenticates
// while it builds the client, so setup needs working credentials.
func NewStandaloneClient(ctx context.Context, primaryEndpoint, readerEndpoint string, opts ...GCPOption) (valkey.Client, error) {
	clientOpt := valkey.ClientOption{
		InitAddress: []string{primaryEndpoint},
		Standalone: valkey.StandaloneOption{
			ReplicaAddress: []string{readerEndpoint},
		},
		SendToReplicas: sendReadsToReplicas,
		Dialer: net.Dialer{
			KeepAlive: defaultKeepAlive,
			Timeout:   defaultDialTimeout,
		},
		ConnWriteTimeout: defaultConnWriteTimeout,
		RetryDelay:       memorystoreRetryDelay, // Correction V9: defined in retry.go
	}
	return newClient(ctx, clientOpt, opts)
}

// newClient applies opts with the constructor's ctx and connects. valkey.NewClient takes no
// context, so ctx is checked once more before dialing.
func newClient(ctx context.Context, clientOpt valkey.ClientOption, opts []GCPOption) (valkey.Client, error) {
	for _, opt := range opts {
		if err := opt(ctx, &clientOpt); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return valkey.NewClient(clientOpt)
}

// sendReadsToReplicas routes read-only commands to the reader endpoint.
func sendReadsToReplicas(cmd valkey.Completed) bool {
	// Fix C5: Exclude blocking commands from replica routing
	return cmd.IsReadOnly() && !cmd.IsBlock()
}
