// Command pacing shows IAMAuthOptions.MaxAuthPerSecond. It opens -conns new connections at
// the same time, first without a limit and then with MaxAuthPerSecond set. With the limit,
// the AUTHs, and so the new connections, are spread out over time.
//
//	go run ./cmd/features/pacing -addr 10.0.0.15:6379 [-conns 10] [-rate 5]
//
// Use it to protect the instance when many connections reconnect at once. Add -local-token
// TOKEN to try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	conns := flag.Int("conns", 10, "connections to open at the same time")
	rate := flag.Float64("rate", 5, "IAMAuthOptions.MaxAuthPerSecond")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	option := valkey.ClientOption{InitAddress: []string{*addr}}

	for _, limit := range []float64{0, *rate} {
		iam := valkeygcp.IAMAuthOptions{
			// At most this many AUTHs per second for this client. 0: no limit.
			MaxAuthPerSecond: limit,
		}
		if *localToken != "" {
			iam.CustomTokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken})
		}
		client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(iam))
		if err != nil {
			log.Fatalf("connect: %v", err)
		}

		// Each dedicated client opens its own connection on its first command.
		start := time.Now()
		var wg sync.WaitGroup
		for i := range *conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dedicated, release := client.Dedicate()
				defer release()
				key := fmt.Sprintf("valkeygcp:pacing:%d", i)
				if err := dedicated.Do(ctx, dedicated.B().Get().Key(key).Build()).Error(); err != nil && !valkey.IsValkeyNil(err) {
					log.Printf("GET %s: %v", key, err)
				}
			}()
		}
		wg.Wait()
		log.Printf("MaxAuthPerSecond %v: %d new connections took %v", limit, *conns, time.Since(start).Round(time.Millisecond))
		client.Close()
	}
}
