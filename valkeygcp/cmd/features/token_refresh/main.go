// Command token_refresh shows tokens being renewed on a live connection while commands keep
// working.
//
// Real tokens last an hour. So that you don't have to wait that long, this example's token
// source says each token expires after -lifetime (1 minute). valkeygcp then fetches a new
// token and re-AUTHs the connection about every half minute. The token itself stays valid on
// the server.
//
//	go run ./cmd/features/token_refresh -addr 10.0.0.15:6379
//	go run ./cmd/features/token_refresh -addr 10.0.0.15:6379 -disable-reauth
//
// With -disable-reauth (IAMAuthOptions.DisableProactiveReauth) the connection keeps its
// first token and no new token is fetched. Add -ca server-ca.pem for in-transit encryption,
// or -local-token TOKEN to try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	lifetime := flag.Duration("lifetime", time.Minute, "token lifetime this example reports")
	duration := flag.Duration("duration", 2*time.Minute, "how long to run")
	disable := flag.Bool("disable-reauth", false, "set IAMAuthOptions.DisableProactiveReauth")
	ca := flag.String("ca", "", "server CA file, for in-transit encryption")
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

	option := valkey.ClientOption{InitAddress: []string{*addr}}
	if *ca != "" {
		option.TLSConfig = loadCA(*ca)
	}
	client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		CustomTokenSource: shortLived{base: base, lifetime: *lifetime},
		// Replace a token this long before it expires. Live connections re-AUTH with the new
		// token in the first half of this window.
		RefreshBuffer: *lifetime / 2,
		// true: no re-AUTH on live connections; only new connections get a fresh token.
		DisableProactiveReauth: *disable,
	}))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	log.Printf("connected; running for %v", *duration)

	// One key, so every command uses the same connection.
	key := "valkeygcp:token_refresh"
	stop := time.After(*duration)
	for i := 1; ; i++ {
		err := client.Do(ctx, client.B().Set().Key(key).Value(time.Now().Format(time.RFC3339)).Ex(10*time.Minute).Build()).Error()
		if err != nil {
			log.Printf("SET #%d failed: %v", i, err)
		} else {
			log.Printf("SET #%d ok", i)
		}
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// shortLived reports a shorter lifetime than the token really has, so that refreshes happen
// within a few minutes. It logs every time valkeygcp asks for a token.
type shortLived struct {
	base     oauth2.TokenSource
	lifetime time.Duration
}

func (s shortLived) Token() (*oauth2.Token, error) {
	tok, err := s.base.Token()
	if err != nil {
		return nil, err
	}
	t := *tok
	t.Expiry = time.Now().Add(s.lifetime)
	log.Printf("token source: new token, reported to expire at %s", t.Expiry.Format("15:04:05"))
	return &t, nil
}

// loadCA returns a TLS configuration that trusts the instance's server CA.
func loadCA(file string) *tls.Config {
	pem, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatalf("no certificate in %s", file)
	}
	return &tls.Config{RootCAs: pool}
}
