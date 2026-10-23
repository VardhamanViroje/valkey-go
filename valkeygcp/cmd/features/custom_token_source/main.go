// Command custom_token_source authenticates with access tokens from your own
// oauth2.TokenSource instead of Application Default Credentials. Here the tokens come from a
// service account key file, and every token fetch is logged.
//
//	go run ./cmd/features/custom_token_source -addr 10.0.0.15:6379 -key-file sa-key.json
//
// The service account needs roles/memorystore.dbConnectionUser on the instance. Add -ca
// server-ca.pem for in-transit encryption, or use -local-token TOKEN instead of -key-file to
// try against a local Valkey started with --requirepass.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint (cluster mode) or primary endpoint, host:port")
	keyFile := flag.String("key-file", "", "service account key file (JSON)")
	ca := flag.String("ca", "", "server CA file, for in-transit encryption")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	// Any oauth2.TokenSource works.
	var source oauth2.TokenSource
	switch {
	case *localToken != "":
		source = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken})
	case *keyFile != "":
		key, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		creds, err := google.CredentialsFromJSONWithType(ctx, key, google.ServiceAccount, valkeygcp.DefaultCloudPlatformScope)
		if err != nil {
			log.Fatalf("key file: %v", err)
		}
		source = creds.TokenSource
	default:
		log.Fatal("set -key-file, for example -key-file sa-key.json")
	}

	option := valkey.ClientOption{InitAddress: []string{*addr}}
	if *ca != "" {
		option.TLSConfig = loadCA(*ca)
	}
	client, err := valkeygcp.NewClient(ctx, option, valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		CustomTokenSource: loggingSource{source},
	}))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		log.Fatalf("PING: %v", err)
	}
	log.Print("connected with tokens from the custom source, PING ok")
}

// loggingSource logs every time valkeygcp asks for a token. valkeygcp caches the token, so
// this happens once at the start and then shortly before each token expires.
type loggingSource struct{ oauth2.TokenSource }

func (s loggingSource) Token() (*oauth2.Token, error) {
	tok, err := s.TokenSource.Token()
	if err != nil {
		log.Printf("token source: %v", err)
		return nil, err
	}
	if tok.Expiry.IsZero() {
		log.Print("token source: new token, no expiry")
	} else {
		log.Printf("token source: new token, expires at %s", tok.Expiry.Format("15:04:05"))
	}
	return tok, nil
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
