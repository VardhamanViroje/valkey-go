// scratch/traffic.go
package main

import (
	"context"
	"fmt"
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

	ctx := context.Background()
	var i uint64
	for {
		i++
		key := fmt.Sprintf("key-%d", i)
		start := time.Now()
		err := client.Do(ctx, client.B().Set().Key(key).Value("val").Build()).Error()
		latency := time.Since(start)

		if err != nil {
			fmt.Printf("❌ [%s] WRITE ERROR: %v (latency: %v)\n", time.Now().Format("15:04:05.000"), err, latency)
		} else {
			fmt.Printf("✅ [%s] WRITE OK (latency: %v)\n", time.Now().Format("15:04:05.000"), latency)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
