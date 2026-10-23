// Command iam_options connects with WithIAMOptions and shows every IAMAuthOptions field.
// WithDefaultIAM() is the same as WithIAMOptions(valkeygcp.IAMAuthOptions{}): every field at
// its default.
//
//	go run ./cmd/features/iam_options -addr 10.0.0.15:6379
//
// Memorystore accepts "default" or the email of the IAM principal as the username. Add
// -local-token TOKEN to try against a local Valkey started with --requirepass.
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
	username := flag.String("username", valkeygcp.DefaultIAMUsername, `AUTH username: "default" or the principal's email`)
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	option := valkey.ClientOption{InitAddress: []string{*addr}}

	iam := valkeygcp.IAMAuthOptions{
		// The AUTH username. Default: "default".
		Username: *username,

		// Where the access tokens come from. Default: Application Default Credentials.
		// See cmd/features/custom_token_source.
		CustomTokenSource: nil,

		// OAuth2 scopes requested from ADC. Default: cloud-platform.
		Scopes: []string{valkeygcp.DefaultCloudPlatformScope},

		// Replace each token this long before it expires; live connections re-AUTH with the
		// new token in the first half of this window. Default: 5 minutes.
		RefreshBuffer: 10 * time.Minute,

		// Give up on one token fetch after this long. Default: 10 seconds.
		FetchTimeout: 5 * time.Second,

		// At most this many AUTHs per second, for example when many connections reconnect at
		// once. Default: 0, no limit. See cmd/features/pacing.
		MaxAuthPerSecond: 50,

		// true stops re-AUTH on live connections; new connections still get a fresh token.
		// Default: false. See cmd/features/token_refresh.
		DisableProactiveReauth: false,

		// Called when a token refresh fails; live connections keep the last valid token.
		// See cmd/features/refresh_failure.
		OnCredentialError: func(err error) {
			log.Printf("token refresh failed, keeping the last token: %v", err)
		},
	}
	if *localToken != "" {
		iam.CustomTokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken})
	}

	client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(iam))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		log.Fatalf("PING: %v", err)
	}
	log.Printf("connected as %q, PING ok", *username)
}
