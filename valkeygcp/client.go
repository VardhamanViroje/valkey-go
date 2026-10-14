package valkeygcp

import (
	"context"
	"net"
	"time"

	"github.com/valkey-io/valkey-go"
)

// GCPOption configures the valkey.ClientOption with Google Cloud specific parameters.
type GCPOption func(*valkey.ClientOption) error

// Connection defaults shared by the constructors and NewClient.
const (
	defaultDialTimeout           = 2 * time.Second
	defaultKeepAlive             = 1 * time.Second
	defaultConnWriteTimeout      = 3 * time.Second
	defaultShardsRefreshInterval = 10 * time.Second // Fix C6: 10s with jitter
)

// NewClusterClient creates a Memorystore Cluster Mode client with discovery pinning,
// fast failover reconnection, and optional IAM authentication.
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

	for _, opt := range opts {
		if err := opt(&clientOpt); err != nil {
			return nil, err
		}
	}

	return valkey.NewClient(clientOpt)
}

// NewStandaloneClient creates a Memorystore Standalone (Cluster Disabled) client with
// automatic read/write splitting between Primary and Reader Endpoints.
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

	for _, opt := range opts {
		if err := opt(&clientOpt); err != nil {
			return nil, err
		}
	}

	return valkey.NewClient(clientOpt)
}

// sendReadsToReplicas routes read-only commands to the reader endpoint.
func sendReadsToReplicas(cmd valkey.Completed) bool {
	// Fix C5: Exclude blocking commands from replica routing
	return cmd.IsReadOnly() && !cmd.IsBlock()
}
