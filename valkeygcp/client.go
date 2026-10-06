package valkeygcp

import (
	"context"
	"net"
	"time"

	"github.com/valkey-io/valkey-go"
)

// NewClusterClient creates a Memorystore Cluster Mode client with discovery pinning,
// fast failover reconnection, and optional IAM authentication.
func NewClusterClient(ctx context.Context, discoveryEndpoint string, opts ...GCPOption) (valkey.Client, error) {
	clientOpt := valkey.ClientOption{
		InitAddress: []string{discoveryEndpoint},
		ClusterOption: valkey.ClusterOption{
			PreferInitAddressRefresh: true,
			ShardsRefreshInterval:    10 * time.Second,
			PreferClusterShards:       true,
		},
		Dialer: net.Dialer{
			KeepAlive: 1 * time.Second,
			Timeout:   2 * time.Second,
		},
		ConnWriteTimeout: 3 * time.Second,
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
		SendToReplicas: func(cmd valkey.Completed) bool {
			return cmd.IsReadOnly() && !cmd.IsBlock()
		},
		Dialer: net.Dialer{
			KeepAlive: 1 * time.Second,
			Timeout:   2 * time.Second,
		},
		ConnWriteTimeout: 3 * time.Second,
	}

	for _, opt := range opts {
		if err := opt(&clientOpt); err != nil {
			return nil, err
		}
	}

	return valkey.NewClient(clientOpt)
}
