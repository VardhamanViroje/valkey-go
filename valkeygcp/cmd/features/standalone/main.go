// Command standalone connects to a Memorystore for Valkey instance with cluster mode
// disabled. Writes go to the primary endpoint; read-only commands go to the reader endpoint.
//
//	go run ./cmd/features/standalone -primary 10.0.0.2:6379 -reader 10.0.0.3:6379
//
// Leave out -reader for an instance without replicas. Add -local-token TOKEN to try against a
// local Valkey started with --requirepass.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

func main() {
	primary := flag.String("primary", "", "primary endpoint, host:port")
	reader := flag.String("reader", "", "reader endpoint, host:port (optional)")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *primary == "" {
		log.Fatal("set -primary, for example -primary 10.0.0.2:6379")
	}
	ctx := context.Background()

	option := valkey.ClientOption{InitAddress: []string{*primary}}
	if *reader != "" {
		// Read-only commands that don't block are sent here.
		option.Standalone.ReplicaAddress = []string{*reader}
	}

	auth := valkeygcp.WithDefaultIAM()
	if *localToken != "" {
		auth = valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken}),
		})
	}

	client, err := valkeygcp.NewClient(ctx, option, auth)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	for addr := range client.Nodes() {
		log.Printf("connected to %s", addr)
	}

	// SET always goes to the primary.
	key := "valkeygcp:standalone"
	if err := client.Do(ctx, client.B().Set().Key(key).Value("hello").Ex(10*time.Minute).Build()).Error(); err != nil {
		log.Fatalf("SET: %v", err)
	}
	log.Printf("SET %s on the primary", key)

	// GET goes to the reader when there is one. Replication is asynchronous, so give it a
	// moment.
	time.Sleep(500 * time.Millisecond)
	val, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
	switch {
	case valkey.IsValkeyNil(err):
		log.Printf("GET %s: not replicated yet", key)
	case err != nil:
		log.Fatalf("GET: %v", err)
	default:
		log.Printf("GET %s = %q", key, val)
	}
}
