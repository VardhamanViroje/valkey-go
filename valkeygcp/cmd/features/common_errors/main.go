// Command common_errors shows the errors you get from common mistakes, so you can recognize
// them: no address, a password together with IAM, missing Application Default Credentials, a
// token the server rejects, and a token source that never answers.
//
//	go run ./cmd/features/common_errors -addr 10.0.0.15:6379
//
// The rejected-token case sends one invalid token. Add -ca server-ca.pem for in-transit
// encryption, or -local-token TOKEN to try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	ca := flag.String("ca", "", "server CA file, for in-transit encryption")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	option := valkey.ClientOption{InitAddress: []string{*addr}}
	if *ca != "" {
		option.TLSConfig = loadCA(*ca)
	}
	auth := valkeygcp.WithDefaultIAM()
	if *localToken != "" {
		auth = valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken}),
		})
	}

	show("No InitAddress", func() error {
		_, err := valkeygcp.NewClient(ctx, valkey.ClientOption{}, auth)
		return err
	})

	show("A password together with IAM", func() error {
		withPassword := option
		withPassword.Password = "secret"
		_, err := valkeygcp.NewClient(ctx, withPassword, auth)
		return err
	})

	show("Missing Application Default Credentials", func() error {
		// Point ADC at a file that doesn't exist, as on a machine without credentials.
		os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(os.TempDir(), "no-such-credentials.json"))
		defer os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
		_, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithDefaultIAM())
		return err
	})

	show("A token the server rejects", func() error {
		client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "not-a-valid-token"}),
		}))
		if err == nil {
			client.Close()
		}
		return err
	})

	show("A token source that never answers (FetchTimeout 2s)", func() error {
		_, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: hangingSource{},
			FetchTimeout:      2 * time.Second,
		}))
		return err
	})
}

// show runs one mistake and prints the error it causes.
func show(mistake string, run func() error) {
	start := time.Now()
	err := run()
	if err == nil {
		log.Printf("%s: no error", mistake)
		return
	}
	log.Printf("%s, after %v:\n    %v", mistake, time.Since(start).Round(time.Millisecond), err)
}

// hangingSource is a token source that never answers.
type hangingSource struct{}

func (hangingSource) Token() (*oauth2.Token, error) { select {} }

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
