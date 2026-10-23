// Command resolve_option shows valkeygcp.ResolveClientOption. It returns the
// valkey.ClientOption that NewClient would connect with: your option with the Memorystore
// defaults and the IAM credentials filled in. Use it to look at the settings, or to build the
// client yourself, for example with valkeyotel.NewClient(option).
//
//	go run ./cmd/features/resolve_option -addr 10.0.0.15:6379
//	go run ./cmd/features/resolve_option -addr 10.0.0.2:6379 -reader 10.0.0.3:6379
//
// Add -local-token TOKEN to try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	reader := flag.String("reader", "", "reader endpoint, host:port (cluster mode disabled, optional)")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	option := valkey.ClientOption{
		InitAddress: []string{*addr},
		// Fields you set yourself are kept; valkeygcp only fills the ones left at zero.
		ConnWriteTimeout: 5 * time.Second,
	}
	if *reader != "" {
		option.Standalone.ReplicaAddress = []string{*reader}
	}
	auth := valkeygcp.WithDefaultIAM()
	if *localToken != "" {
		auth = valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken}),
		})
	}

	resolved, err := valkeygcp.ResolveClientOption(ctx, option, auth)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	fmt.Println("InitAddress:                          ", resolved.InitAddress)
	fmt.Println("Standalone.ReplicaAddress:            ", resolved.Standalone.ReplicaAddress)
	fmt.Println("Dialer.Timeout:                       ", resolved.Dialer.Timeout)
	fmt.Println("Dialer.KeepAlive:                     ", resolved.Dialer.KeepAlive)
	fmt.Println("ConnWriteTimeout (yours):             ", resolved.ConnWriteTimeout)
	fmt.Println("ClusterOption.ShardsRefreshInterval:  ", resolved.ClusterOption.ShardsRefreshInterval)
	fmt.Println("ClusterOption.PreferInitAddressRefresh:", resolved.ClusterOption.PreferInitAddressRefresh)
	fmt.Println("ClusterOption.PreferClusterShards:    ", resolved.ClusterOption.PreferClusterShards)
	fmt.Println("SendToReplicas set:                   ", resolved.SendToReplicas != nil)
	fmt.Println("RetryDelay set:                       ", resolved.RetryDelay != nil)
	fmt.Println("AuthCredentialsFn set (IAM):          ", resolved.AuthCredentialsFn != nil)

	// Build the client yourself from the resolved option.
	client, err := valkey.NewClient(resolved)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		log.Fatalf("PING: %v", err)
	}
	log.Printf("valkey.NewClient connected with the resolved option, %s mode, PING ok", client.Mode())
}
