// Command live_e2e keeps SET and GET traffic running against a cluster-mode Memorystore for
// Valkey instance with IAM authentication, to check that requests keep succeeding while the
// IAM token is refreshed. valkeygcp schedules a re-AUTH on each live connection 2.5 to 5
// minutes before its token expires, and valkey-go then sends AUTH with a new token. Access
// tokens last an hour, so leave the program running for more than an hour.
//
// It needs a host that can reach the instance's discovery endpoint, such as a VM in the
// instance's VPC network, and an instance that uses IAM authentication and has in-transit
// encryption disabled, because the program connects without TLS. The tokens come from
// Application Default Credentials; that principal needs roles/memorystore.dbConnectionUser.
// Run it from the valkeygcp directory and stop it with Ctrl+C:
//
//	MEMORYSTORE_TEST_DISCOVERY_ENDPOINT=10.0.0.15:6379 go run ./cmd/live_e2e
//
// It runs one SET/GET pair every 200ms, logs each failure, and logs the counts after every
// 300 successful pairs, about once a minute.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	endpoint := os.Getenv("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT")
	if endpoint == "" {
		log.Fatal("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT environment variable must be set (e.g. 10.0.0.15:6379)")
	}

	ctx := context.Background()
	log.Printf("Connecting to Memorystore at %s with Native IAM Auth...", endpoint)

	client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{InitAddress: []string{endpoint}},
		valkeygcp.WithTopology(valkeygcp.TopologyCluster), // the discovery endpoint of a cluster-mode instance
		valkeygcp.WithDefaultIAM(),                        // IAM tokens from Application Default Credentials
		// The instance must have in-transit encryption disabled: this program connects
		// without TLS. valkeygcp refuses to send IAM tokens in plaintext unless TLS is
		// turned off explicitly, as here.
		valkeygcp.WithTLS(valkeygcp.TLSOptions{Mode: valkeygcp.TLSDisabled}),
	)
	if err != nil {
		log.Fatalf("Failed to create Memorystore client: %v", err)
	}
	defer client.Close()

	// Initial PING to verify authentication handshake
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		log.Fatalf("Initial PING failed! Authentication rejected: %v", err)
	}
	log.Println("✅ Initial RESP3 HELLO 3 AUTH handshake succeeded!")

	// Run continuous traffic loop
	var successCount uint64
	var errorCount uint64
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	log.Println("Running continuous traffic test. Monitoring across token rotation (press Ctrl+C to stop)...")

	startTime := time.Now()
	for {
		select {
		case <-ticker.C:
			key := fmt.Sprintf("e2e-iam-key-%d", time.Now().UnixNano()%100)
			val := fmt.Sprintf("val-%d", time.Now().UnixNano())

			// Execute SET
			err := client.Do(ctx, client.B().Set().Key(key).Value(val).Ex(60*time.Second).Build()).Error()
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				log.Printf("❌ SET failed: %v", err)
				continue
			}

			// Execute GET
			getVal, err := client.Do(ctx, client.B().Get().Key(key).Build()).ToString()
			if err != nil || getVal != val {
				atomic.AddUint64(&errorCount, 1)
				log.Printf("❌ GET failed or value mismatch: %v", err)
				continue
			}

			count := atomic.AddUint64(&successCount, 1)
			if count%300 == 0 {
				log.Printf("[Elapsed: %v] Operations: %d succeeded, %d failed",
					time.Since(startTime).Round(time.Second),
					atomic.LoadUint64(&successCount),
					atomic.LoadUint64(&errorCount),
				)
			}

		case <-stopChan:
			log.Println("Stopping test...")
			return
		}
	}
}
