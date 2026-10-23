// Command quickstart connects to a cluster-mode Memorystore for Valkey instance with IAM
// authentication and runs a few commands. Start here.
//
// Run it on a VM or GKE pod in the instance's VPC network, as an identity that has
// roles/memorystore.dbConnectionUser on the instance:
//
//	go run ./cmd/features/quickstart -addr 10.0.0.15:6379
//
// Add -ca server-ca.pem if the instance uses in-transit encryption. To try it without
// Memorystore, start a local Valkey with --requirepass TOKEN and add -local-token TOKEN.
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
)

func main() {
	addr := flag.String("addr", "", "discovery endpoint of the instance, host:port")
	ca := flag.String("ca", "", "server CA file, for in-transit encryption")
	localToken := flag.String("local-token", "", "password of a local Valkey, to try without Memorystore")
	flag.Parse()
	if *addr == "" {
		log.Fatal("set -addr, for example -addr 10.0.0.15:6379")
	}
	ctx := context.Background()

	// The same valkey.ClientOption you would pass to valkey.NewClient.
	option := valkey.ClientOption{InitAddress: []string{*addr}}
	if *ca != "" {
		option.TLSConfig = loadCA(*ca)
	}

	// IAM access tokens from Application Default Credentials (ADC) instead of a password.
	auth := valkeygcp.WithDefaultIAM()
	if *localToken != "" {
		auth = valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
			CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *localToken}),
		})
	}

	client, err := valkeygcp.NewClient(ctx, option, auth)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()
	log.Printf("connected, %s mode", client.Mode())

	// Use the client like any valkey.Client. Tokens are renewed in the background.
	err = client.Do(ctx, client.B().Set().Key("valkeygcp:quickstart").Value("hello").Ex(10*time.Minute).Build()).Error()
	if err != nil {
		log.Fatalf("SET: %v", err)
	}
	val, err := client.Do(ctx, client.B().Get().Key("valkeygcp:quickstart").Build()).ToString()
	if err != nil {
		log.Fatalf("GET: %v", err)
	}
	log.Printf("GET valkeygcp:quickstart = %q", val)
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
