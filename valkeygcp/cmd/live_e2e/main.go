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

	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	endpoint := os.Getenv("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT")
	if endpoint == "" {
		log.Fatal("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT environment variable must be set (e.g. 10.0.0.15:6379)")
	}

	ctx := context.Background()
	log.Printf("Connecting to Memorystore at %s with Native IAM Auth...", endpoint)

	client, err := valkeygcp.NewClusterClient(ctx, endpoint,
		valkeygcp.WithDefaultIAM(),
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
