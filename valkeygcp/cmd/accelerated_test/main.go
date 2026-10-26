// Command accelerated_test shows how valkeygcp's IAM token provider caches tokens and
// schedules the proactive re-AUTH of live connections. The tokens here expire after 10
// seconds instead of an hour, so the timing shows in seconds.
//
// A fake token source (IAMAuthOptions.CustomTokenSource) hands out the tokens, so the
// program needs no credentials, instance or network. Run it from the valkeygcp directory:
//
//	go run ./cmd/accelerated_test
//
// It asks the provider's AuthCredentialsFn for credentials five times, one second apart, as
// valkey-go does for each new connection, and logs when the next re-AUTH would be due
// (AuthCredentials.RefreshAfter). With RefreshBuffer set to 3s, the provider's cache treats
// each token as expired 3s before its real expiry, so all five calls get the first token.
// RefreshAfter falls in the first half of those last 3s, 7s to 8.5s after the token was
// issued, picked at random so that connections don't re-AUTH at once. The cache already
// treats the token as expired by then, so the re-AUTH gets a new token, not the old one.
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

// shortLivedTokenSource is a fake oauth2.TokenSource. Each call returns a new token that
// expires 10s later; rotations counts the tokens handed out.
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
		RefreshBuffer:     3 * time.Second, // re-AUTH 7s to 8.5s after each token is issued
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
		log.Printf("Token acquired. Next Refresh Scheduled in: %v",
			time.Until(creds.RefreshAfter).Round(time.Millisecond),
		)
		time.Sleep(1 * time.Second)
	}
	log.Printf("✅ Stress test completed successfully with %d token rotations!", atomic.LoadInt64(&mockSource.rotations))
}
