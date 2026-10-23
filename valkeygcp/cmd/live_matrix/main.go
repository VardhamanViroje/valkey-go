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
// disabled) and VALKEY_GCP_TLS_CA_FILE when in-transit encryption is on. For an instance with
// in-transit encryption disabled, set VALKEY_GCP_TLS_MODE=disabled: valkeygcp refuses to send
// IAM or Token Auth credentials without TLS unless TLS is turned off explicitly.
//
// Both paths read VALKEY_GCP_TOKEN_SECRET and VALKEY_GCP_TOKEN_USERNAME (TOKEN_AUTH) and
// VALKEY_GCP_USERNAME_STRATEGY=principal-email (IAM username, test L6-B).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	option, opts, err := config()
	if err != nil {
		log.Fatal(err)
	}
	client, err := valkeygcp.NewClient(ctx, option, opts...)
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

// config maps the environment to the valkey.ClientOption and the valkeygcp options for
// NewClient.
func config() (valkey.ClientOption, []valkeygcp.Option, error) {
	var option valkey.ClientOption
	opts := []valkeygcp.Option{
		valkeygcp.OnCredentialError(func(err error) { log.Printf("⚠️ credential refresh failed, serving the last token: %v", err) }),
	}
	instance := os.Getenv("VALKEY_GCP_INSTANCE") // auto-discovery path
	if instance != "" {
		// Discovered endpoints win unless overridden on purpose; keep the two paths apart: the
		// endpoint variables are only read without an instance.
		opts = append(opts, valkeygcp.WithInstance(instance))
	} else {
		// WithTopology keeps the checks that go with the endpoint's cluster mode.
		discovery, primary := os.Getenv("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT"), os.Getenv("VALKEY_GCP_PRIMARY_ENDPOINT")
		switch {
		case discovery != "" && primary != "":
			return valkey.ClientOption{}, nil, errors.New("MEMORYSTORE_TEST_DISCOVERY_ENDPOINT and VALKEY_GCP_PRIMARY_ENDPOINT are both set: want one")
		case discovery != "":
			option.InitAddress = []string{discovery}
			opts = append(opts, valkeygcp.WithTopology(valkeygcp.TopologyCluster))
		case primary != "":
			option.InitAddress = []string{primary}
			opts = append(opts, valkeygcp.WithTopology(valkeygcp.TopologyClusterDisabled))
		}
		if reader := os.Getenv("VALKEY_GCP_READER_ENDPOINT"); reader != "" {
			option.Standalone.ReplicaAddress = []string{reader}
		}
	}
	token := valkeygcp.TokenAuthOptions{
		SecretVersion: os.Getenv("VALKEY_GCP_TOKEN_SECRET"),
		Username:      os.Getenv("VALKEY_GCP_TOKEN_USERNAME"), // "" = default user
	}
	iam := valkeygcp.WithDefaultIAM() // Application Default Credentials
	principalEmail := os.Getenv("VALKEY_GCP_USERNAME_STRATEGY") == "principal-email"
	if principalEmail {
		iam = valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{UsernameStrategy: valkeygcp.UsernamePrincipalEmail})
	}
	tlsOpt := valkeygcp.TLSOptions{CAFile: os.Getenv("VALKEY_GCP_TLS_CA_FILE")}
	switch mode := os.Getenv("VALKEY_GCP_TLS_MODE"); mode {
	case "":
	case "disabled":
		tlsOpt.Mode = valkeygcp.TLSDisabled
	default:
		return valkey.ClientOption{}, nil, fmt.Errorf("VALKEY_GCP_TLS_MODE=%q: want disabled or unset", mode)
	}
	opts = append(opts, valkeygcp.WithTLS(tlsOpt))
	switch mode := os.Getenv("VALKEY_GCP_AUTH_MODE"); mode {
	case "":
		// With an instance, the instance's auth mode picks one of the options passed. Without
		// one, the variables decide: a token secret means Token Auth,
		// VALKEY_GCP_USERNAME_STRATEGY means IAM, and both is an error.
		if instance != "" || principalEmail {
			opts = append(opts, iam)
		}
		if token.SecretVersion != "" {
			opts = append(opts, valkeygcp.WithTokenAuth(token))
		}
	case "iam":
		opts = append(opts, iam)
	case "token":
		opts = append(opts, valkeygcp.WithTokenAuth(token)) // TOKEN_AUTH fails without VALKEY_GCP_TOKEN_SECRET
	case "disabled":
		// No auth option.
	default:
		return valkey.ClientOption{}, nil, fmt.Errorf("VALKEY_GCP_AUTH_MODE=%q: want iam, token or disabled", mode)
	}
	return option, opts, nil
}
