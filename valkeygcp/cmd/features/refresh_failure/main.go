// Command refresh_failure shows what happens when the token source breaks after the client
// has connected. OnCredentialError reports each failed refresh, the connection keeps its last
// valid token, and the commands keep working. With -hang the source never answers, and
// FetchTimeout stops each fetch.
//
//	go run ./cmd/features/refresh_failure -addr 10.0.0.15:6379
//	go run ./cmd/features/refresh_failure -addr 10.0.0.15:6379 -hang
//
// Like cmd/features/token_refresh, the token source reports a short lifetime (-lifetime), so
// the first refresh comes within the run; the token stays valid on the server. A failed
// refresh is retried about 30 seconds later.
//
// Once the last token has expired, live connections skip the re-AUTH and stay authenticated,
// but a new connection can't authenticate until the source works again. That's why every
// command here uses one key, and so one connection.
//
// Add -local-token TOKEN to try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	lifetime := flag.Duration("lifetime", 30*time.Second, "token lifetime this example reports")
	duration := flag.Duration("duration", 90*time.Second, "how long to run")
	hang := flag.Bool("hang", false, "make the token source hang instead of failing")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	var base oauth2.TokenSource
	if *localToken != "" {
		base = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken})
	} else {
		var err error
		if base, err = google.DefaultTokenSource(ctx, valkeygcp.DefaultCloudPlatformScope); err != nil {
			log.Fatalf("Application Default Credentials: %v", err)
		}
	}
	source := &breakableSource{base: base, lifetime: *lifetime, hang: *hang}

	option := valkey.ClientOption{InitAddress: []string{*addr}}
	client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		CustomTokenSource: source,
		RefreshBuffer:     *lifetime / 2,
		// Give up on one token fetch after 3 seconds.
		FetchTimeout: 3 * time.Second,
		// Called for every failed refresh; live connections keep the last valid token.
		OnCredentialError: func(err error) {
			log.Printf("OnCredentialError: %v", err)
		},
	}))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	key := "valkeygcp:refresh_failure"
	set := func(i int) {
		err := client.Do(ctx, client.B().Set().Key(key).Value(time.Now().Format(time.RFC3339)).Ex(10*time.Minute).Build()).Error()
		if err != nil {
			log.Printf("SET #%d failed: %v", i, err)
		} else {
			log.Printf("SET #%d ok", i)
		}
	}
	set(0) // opens the connection while the source still works

	source.broken.Store(true)
	log.Printf("the token source is broken from now on; running for %v", *duration)
	stop := time.After(*duration)
	for i := 1; ; i++ {
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
			set(i)
		}
	}
}

// breakableSource hands out tokens with a short reported lifetime until broken is set. Then
// every fetch fails, or with hang never answers.
type breakableSource struct {
	base     oauth2.TokenSource
	lifetime time.Duration
	hang     bool
	broken   atomic.Bool
}

func (s *breakableSource) Token() (*oauth2.Token, error) {
	if s.broken.Load() {
		if s.hang {
			log.Print("token source: hanging")
			select {} // never answers; FetchTimeout stops the wait
		}
		log.Print("token source: failing")
		return nil, errors.New("token endpoint unavailable")
	}
	tok, err := s.base.Token()
	if err != nil {
		return nil, err
	}
	t := *tok
	t.Expiry = time.Now().Add(s.lifetime)
	log.Printf("token source: new token, reported to expire at %s", t.Expiry.Format("15:04:05"))
	return &t, nil
}
