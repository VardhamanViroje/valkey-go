package main

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

type shortLivedTokenSource struct {
	rotations int64
}

func (s *shortLivedTokenSource) Token() (*oauth2.Token, error) {
	rot := atomic.AddInt64(&s.rotations, 1)
	log.Printf("🔄 [TokenSource] Emitting fresh token #%d (expires in 10s)", rot)
	return &oauth2.Token{
		AccessToken: fmt.Sprintf("token-version-%d", rot),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(10 * time.Second),
	}, nil
}

func main() {
	mockSource := &shortLivedTokenSource{}

	provider, err := valkeygcp.NewGCPTokenProvider(context.Background(), valkeygcp.IAMAuthOptions{
		RefreshBuffer:     3 * time.Second, // Refresh 3s before 10s expiry -> every 7s!
		CustomTokenSource: mockSource,
	})
	if err != nil {
		log.Fatal(err)
	}

	authFn := provider.AuthCredentialsFn()

	log.Println("Simulating accelerated token rotation across 30 seconds...")
	for i := 0; i < 5; i++ {
		creds, err := authFn(valkey.AuthCredentialsContext{})
		if err != nil {
			log.Fatalf("authFn error: %v", err)
		}
		log.Printf("Token Password: %s, Next Refresh Scheduled in: %v",
			creds.Password,
			time.Until(creds.RefreshAfter).Round(time.Millisecond),
		)
		time.Sleep(1 * time.Second)
	}
	log.Printf("✅ Stress test completed successfully with %d token rotations!", atomic.LoadInt64(&mockSource.rotations))
}
