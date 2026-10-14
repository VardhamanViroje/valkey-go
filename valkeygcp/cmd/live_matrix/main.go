// Command live_matrix runs the Level 6 live auth-mode matrix (SOW acceptance) against a real
// Memorystore for Valkey instance: it connects through valkeygcp.NewClient, PINGs every node
// (authentication and TLS SAN coverage per node IP) and runs a SET.
//
// Auto-discovery path (needs memorystore.instances.get):
//
//	VALKEY_GCP_INSTANCE=projects/P/locations/R/instances/I go run ./cmd/live_matrix
//
// Explicit path (no control-plane call): leave VALKEY_GCP_INSTANCE unset and set
// MEMORYSTORE_TEST_DISCOVERY_ENDPOINT (cluster) or VALKEY_GCP_PRIMARY_ENDPOINT and optionally
// VALKEY_GCP_READER_ENDPOINT (cluster-disabled), plus VALKEY_GCP_AUTH_MODE (iam, token or
// disabled) and VALKEY_GCP_TLS_CA_FILE when in-transit encryption is on.
//
// Both paths read VALKEY_GCP_TOKEN_SECRET and VALKEY_GCP_TOKEN_USERNAME (TOKEN_AUTH) and
// VALKEY_GCP_USERNAME_STRATEGY=principal-email (IAM username, test L6-B).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := config()
	if err != nil {
		log.Fatal(err)
	}
	client, err := valkeygcp.NewClient(ctx, cfg)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Every node: proves authentication and TLS SAN coverage per node IP.
	for addr, node := range client.Nodes() {
		if err := node.Do(ctx, node.B().Ping().Build()).Error(); err != nil {
			log.Fatalf("PING %s: %v", addr, err)
		}
		log.Printf("✅ %s authenticated (client mode=%s)", addr, client.Mode())
	}
	if err := client.Do(ctx, client.B().Set().Key("valkeygcp:matrix").Value("ok").Ex(time.Minute).Build()).Error(); err != nil {
		log.Fatalf("SET: %v", err)
	}
	log.Println("✅ SET succeeded")
}

func config() (valkeygcp.Config, error) {
	cfg := valkeygcp.Config{
		Instance:          os.Getenv("VALKEY_GCP_INSTANCE"), // auto-discovery path
		DiscoveryEndpoint: os.Getenv("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT"),
		PrimaryEndpoint:   os.Getenv("VALKEY_GCP_PRIMARY_ENDPOINT"),
		ReaderEndpoint:    os.Getenv("VALKEY_GCP_READER_ENDPOINT"),
		TLS:               valkeygcp.TLSOptions{CAFile: os.Getenv("VALKEY_GCP_TLS_CA_FILE")},
		Auth: valkeygcp.AuthOptions{
			OnCredentialError: func(err error) { log.Printf("⚠️ credential refresh failed, serving the last token: %v", err) },
		},
	}
	if cfg.Instance != "" {
		// Discovered endpoints win unless overridden on purpose; keep the two paths apart.
		cfg.DiscoveryEndpoint, cfg.PrimaryEndpoint, cfg.ReaderEndpoint = "", "", ""
	}
	if s := os.Getenv("VALKEY_GCP_TOKEN_SECRET"); s != "" {
		cfg.Auth.Token = valkeygcp.TokenAuthOptions{
			SecretVersion: s,
			Username:      os.Getenv("VALKEY_GCP_TOKEN_USERNAME"), // "" = default user
		}
	}
	if os.Getenv("VALKEY_GCP_USERNAME_STRATEGY") == "principal-email" {
		cfg.Auth.IAM.UsernameStrategy = valkeygcp.UsernamePrincipalEmail
	}
	switch mode := os.Getenv("VALKEY_GCP_AUTH_MODE"); mode {
	case "":
	case "iam":
		cfg.Auth.Mode = valkeygcp.AuthIAM
	case "token":
		cfg.Auth.Mode = valkeygcp.AuthToken
	case "disabled":
		cfg.Auth.Mode = valkeygcp.AuthDisabled
	default:
		return valkeygcp.Config{}, fmt.Errorf("VALKEY_GCP_AUTH_MODE=%q: want iam, token or disabled", mode)
	}
	return cfg, nil
}
