// scratch/traffic.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valkey-io/valkey-go"
)

/*
go run main.go > output.log 2>&1
*/

func main() {
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{"127.0.0.1:7001"},
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("🚀 Starting Valkey Comprehensive Cluster Traffic Generator...")

	// 1. [DO-WRITE] Standard Single Write (every 200ms) - Fast fails on node crash
	go func() {
		var j uint64
		for ctx.Err() == nil {
			j++
			key := fmt.Sprintf("key-write-%d", j)
			start := time.Now()
			err := client.Do(ctx, client.B().Set().Key(key).Value("val").Build()).Error()
			latency := time.Since(start)

			if err != nil {
				fmt.Printf("❌ [%s] [DO-WRITE] key=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), key, err, latency)
			} else {
				fmt.Printf("✅ [%s] [DO-WRITE] key=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), key, latency)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	// 2. [DO-READ] Standard Single Read (every 10ms) - Retries & preempts singleflight
	go func() {
		var i uint64
		for ctx.Err() == nil {
			i++
			key := fmt.Sprintf("key-read-%d", i)
			start := time.Now()
			err := client.Do(ctx, client.B().Get().Key(key).Build()).Error()
			latency := time.Since(start)

			if err != nil && !valkey.IsValkeyNil(err) {
				fmt.Printf("❌ [%s] [DO-READ] key=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), key, err, latency)
			} else {
				fmt.Printf("✅ [%s] [DO-READ] key=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), key, latency)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// 3. [MULTI-WRITE] Multi / Pipelined Write (every 300ms) - Fast fails on node crash
	go func() {
		var m uint64
		for ctx.Err() == nil {
			m++
			k1 := fmt.Sprintf("multi-w1-%d", m)
			k2 := fmt.Sprintf("multi-w2-%d", m)
			start := time.Now()
			resps := client.DoMulti(ctx,
				client.B().Set().Key(k1).Value("v1").Build(),
				client.B().Set().Key(k2).Value("v2").Build(),
			)
			latency := time.Since(start)

			var firstErr error
			for _, r := range resps {
				if err := r.Error(); err != nil {
					firstErr = err
					break
				}
			}
			if firstErr != nil {
				fmt.Printf("❌ [%s] [MULTI-WRITE] keys=[%s, %s] ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, firstErr, latency)
			} else {
				fmt.Printf("✅ [%s] [MULTI-WRITE] keys=[%s, %s] OK (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, latency)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()

	// 4. [MULTI-READ] Multi / Pipelined Read (every 25ms) - Retries & preempts singleflight in rebucketRetries
	go func() {
		var m uint64
		for ctx.Err() == nil {
			m++
			k1 := fmt.Sprintf("multi-r1-%d", m)
			k2 := fmt.Sprintf("multi-r2-%d", m)
			start := time.Now()
			resps := client.DoMulti(ctx,
				client.B().Get().Key(k1).Build(),
				client.B().Get().Key(k2).Build(),
			)
			latency := time.Since(start)

			var firstErr error
			for _, r := range resps {
				if err := r.Error(); err != nil && !valkey.IsValkeyNil(err) {
					firstErr = err
					break
				}
			}
			if firstErr != nil {
				fmt.Printf("❌ [%s] [MULTI-READ] keys=[%s, %s] ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, firstErr, latency)
			} else {
				fmt.Printf("✅ [%s] [MULTI-READ] keys=[%s, %s] OK (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, latency)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()

	// 5. [CACHE-READ] Client-Side Cache Read (every 30ms) - Retries & preempts singleflight in DoCache
	go func() {
		var c uint64
		for ctx.Err() == nil {
			c++
			key := fmt.Sprintf("cache-key-%d", c)
			start := time.Now()
			err := client.DoCache(ctx, client.B().Get().Key(key).Cache(), 10*time.Second).Error()
			latency := time.Since(start)

			if err != nil && !valkey.IsValkeyNil(err) {
				fmt.Printf("❌ [%s] [CACHE-READ] key=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), key, err, latency)
			} else {
				fmt.Printf("✅ [%s] [CACHE-READ] key=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), key, latency)
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()

	// 6. [MULTICACHE-READ] Client-Side Multi Cache Read (every 35ms) - Retries & preempts singleflight in DoMultiCache
	go func() {
		var mc uint64
		for ctx.Err() == nil {
			mc++
			k1 := fmt.Sprintf("mcache-a-%d", mc)
			k2 := fmt.Sprintf("mcache-b-%d", mc)
			start := time.Now()
			resps := client.DoMultiCache(ctx,
				valkey.CT(client.B().Get().Key(k1).Cache(), 10*time.Second),
				valkey.CT(client.B().Get().Key(k2).Cache(), 10*time.Second),
			)
			latency := time.Since(start)

			var firstErr error
			for _, r := range resps {
				if err := r.Error(); err != nil && !valkey.IsValkeyNil(err) {
					firstErr = err
					break
				}
			}
			if firstErr != nil {
				fmt.Printf("❌ [%s] [MULTICACHE-READ] keys=[%s, %s] ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, firstErr, latency)
			} else {
				fmt.Printf("✅ [%s] [MULTICACHE-READ] keys=[%s, %s] OK (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, latency)
			}
			time.Sleep(35 * time.Millisecond)
		}
	}()

	// 7. [DEDICATED-WRITE] Dedicated Client Single Write (every 400ms) - Fast fails on node crash
	go func() {
		var dw uint64
		for ctx.Err() == nil {
			dw++
			key := fmt.Sprintf("dedi-w-%d", dw)
			start := time.Now()
			err := client.Dedicated(func(d valkey.DedicatedClient) error {
				return d.Do(ctx, client.B().Set().Key(key).Value("val").Build()).Error()
			})
			latency := time.Since(start)

			if err != nil {
				fmt.Printf("❌ [%s] [DEDICATED-WRITE] key=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), key, err, latency)
			} else {
				fmt.Printf("✅ [%s] [DEDICATED-WRITE] key=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), key, latency)
			}
			time.Sleep(400 * time.Millisecond)
		}
	}()

	// 8. [DEDICATED-READ] Dedicated Client Single Read (every 20ms) - Retries & preempts singleflight in dedicated.Do
	go func() {
		var dr uint64
		for ctx.Err() == nil {
			dr++
			key := fmt.Sprintf("dedi-r-%d", dr)
			start := time.Now()
			err := client.Dedicated(func(d valkey.DedicatedClient) error {
				return d.Do(ctx, client.B().Get().Key(key).Build()).Error()
			})
			latency := time.Since(start)

			if err != nil && !valkey.IsValkeyNil(err) {
				fmt.Printf("❌ [%s] [DEDICATED-READ] key=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), key, err, latency)
			} else {
				fmt.Printf("✅ [%s] [DEDICATED-READ] key=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), key, latency)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// 9. [DEDICATED-MULTI] Dedicated Client Multi Read (every 50ms) - Retries & preempts singleflight in dedicated.DoMulti
	// Note: in cluster mode, dedicated multi requires keys in the same slot (using hashtag {tag})
	go func() {
		var dm uint64
		for ctx.Err() == nil {
			dm++
			tag := fmt.Sprintf("{tag-%d}", dm)
			k1 := tag + "a"
			k2 := tag + "b"
			start := time.Now()
			err := client.Dedicated(func(d valkey.DedicatedClient) error {
				resps := d.DoMulti(ctx,
					client.B().Get().Key(k1).Build(),
					client.B().Get().Key(k2).Build(),
				)
				for _, r := range resps {
					if err := r.Error(); err != nil && !valkey.IsValkeyNil(err) {
						return err
					}
				}
				return nil
			})
			latency := time.Since(start)

			if err != nil {
				fmt.Printf("❌ [%s] [DEDICATED-MULTI] keys=[%s, %s] ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, err, latency)
			} else {
				fmt.Printf("✅ [%s] [DEDICATED-MULTI] keys=[%s, %s] OK (latency: %v)\n", time.Now().Format("15:04:05.000"), k1, k2, latency)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// 10. [PUBSUB] Cluster PubSub (Receive & Dedicated Receive with Publisher)
	go func() {
		channel := "cluster-traffic-ch"
		for ctx.Err() == nil {
			err := client.Receive(ctx, client.B().Subscribe().Channel(channel).Build(), func(msg valkey.PubSubMessage) {})
			if err != nil && err != valkey.ErrClosing && ctx.Err() == nil {
				fmt.Printf("⚠️ [%s] [PUBSUB-RECV] channel=%s Reconnecting after: %v\n", time.Now().Format("15:04:05.000"), channel, err)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	go func() {
		var p uint64
		channel := "cluster-traffic-ch"
		for ctx.Err() == nil {
			p++
			start := time.Now()
			msg := fmt.Sprintf("msg-%d", p)
			err := client.Do(ctx, client.B().Publish().Channel(channel).Message(msg).Build()).Error()
			latency := time.Since(start)
			if err != nil {
				fmt.Printf("❌ [%s] [PUBSUB-PUB] channel=%s, msg=%s ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), channel, msg, err, latency)
			} else {
				fmt.Printf("✅ [%s] [PUBSUB-PUB] channel=%s, msg=%s OK (latency: %v)\n", time.Now().Format("15:04:05.000"), channel, msg, latency)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Block until interrupted
	<-ctx.Done()
	fmt.Println("🛑 Shutting down traffic generator...")
}
