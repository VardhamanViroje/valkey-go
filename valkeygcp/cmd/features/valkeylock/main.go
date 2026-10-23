// Command valkeylock uses valkeygcp.NewClient as the ClientBuilder of valkeylock, so the
// distributed lock authenticates with IAM. valkeylimiter and valkeyaside take a ClientBuilder
// the same way.
//
//	go run ./cmd/features/valkeylock -addr 10.0.0.15:6379
//
// Add -ca server-ca.pem for in-transit encryption, or -local-token TOKEN to try against a
// local Valkey started with --requirepass.
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
	"github.com/valkey-io/valkey-go/valkeylock"
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

	locker, err := valkeylock.NewLocker(valkeylock.LockerOption{
		ClientOption: option,
		// valkeylock adds its own settings to the option; valkeygcp.NewClient keeps them and
		// adds IAM authentication.
		ClientBuilder: func(o valkey.ClientOption) (valkey.Client, error) {
			return valkeygcp.NewClient(ctx, o, auth)
		},
	})
	if err != nil {
		log.Fatalf("locker: %v", err)
	}
	defer locker.Close()

	lockCtx, release, err := locker.WithContext(ctx, "valkeygcp-example")
	if err != nil {
		log.Fatalf("lock: %v", err)
	}
	log.Print("lock acquired")
	select {
	case <-lockCtx.Done(): // the lock was lost
		log.Fatalf("lock lost: %v", lockCtx.Err())
	case <-time.After(2 * time.Second): // pretend to work
	}
	release()
	log.Print("lock released")
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
