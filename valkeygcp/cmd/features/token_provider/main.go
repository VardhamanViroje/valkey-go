// Command token_provider uses valkeygcp.NewGCPTokenProvider on its own. It fetches an IAM
// access token, shows the credentials valkey-go would send, and connects with plain
// valkey.NewClient and ClientOption.AuthCredentialsFn.
//
//	go run ./cmd/features/token_provider -addr 10.0.0.15:6379
//
// Without valkeygcp.NewClient, the Memorystore defaults (timeouts, retries, cluster settings)
// aren't filled in. The token is never printed. Add -local-token TOKEN to try against a local
// Valkey started with --requirepass.
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
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	iam := valkeygcp.IAMAuthOptions{} // Application Default Credentials
	if *localToken != "" {
		iam.CustomTokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken})
	}
	provider, err := valkeygcp.NewGCPTokenProvider(ctx, iam)
	if err != nil {
		log.Fatalf("token provider: %v", err)
	}

	// The current access token, fetched and cached by the provider.
	tok, err := provider.Token(ctx)
	if err != nil {
		log.Fatalf("token: %v", err)
	}
	if tok.Expiry.IsZero() {
		log.Printf("token: %d characters, no expiry", len(tok.AccessToken))
	} else {
		log.Printf("token: %d characters, expires in %v", len(tok.AccessToken), time.Until(tok.Expiry).Round(time.Second))
	}

	// What valkey-go sends with AUTH, and when it re-AUTHs.
	creds, err := provider.AuthCredentialsFn()(valkey.AuthCredentialsContext{})
	if err != nil {
		log.Fatalf("credentials: %v", err)
	}
	if creds.RefreshAfter.IsZero() {
		log.Printf("AUTH %s <token>, no re-AUTH scheduled", creds.Username)
	} else {
		log.Printf("AUTH %s <token>, re-AUTH in %v", creds.Username, time.Until(creds.RefreshAfter).Round(time.Second))
	}

	// Plug the provider into a plain valkey.ClientOption.
	option := valkey.ClientOption{
		InitAddress:       []string{*addr},
		AuthCredentialsFn: provider.AuthCredentialsFn(),
	}
	client, err := valkey.NewClient(option)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		log.Fatalf("PING: %v", err)
	}
	log.Printf("valkey.NewClient connected with the provider, %s mode, PING ok", client.Mode())
}
