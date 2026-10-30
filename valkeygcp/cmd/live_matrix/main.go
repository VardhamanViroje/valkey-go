// Command live_matrix checks one auth and TLS setup against a real Memorystore for Valkey
// instance. It connects through valkeygcp.NewClient, PINGs every node and runs a SET, and
// stops with an error at the first failure. Each node is a separate connection with its
// own AUTH and, with TLS, its own certificate check, which passes only if the certificate
// lists that node's IP address. Run it once for each setup to cover: auth mode (IAM, Token
// Auth or none), in-transit encryption on or off, cluster mode enabled or disabled, and the
// IAM username.
//
// Run it from the valkeygcp directory on a host that can reach the instance's endpoints,
// such as a VM in its VPC network. Every Google call uses Application Default Credentials,
// whose principal needs roles/memorystore.dbConnectionUser for IAM authentication and
// roles/secretmanager.secretAccessor on the token secret for Token Auth.
//
// Auto-discovery path: valkeygcp reads the endpoints, auth mode and TLS settings from the
// instance, which needs memorystore.instances.get (roles/memorystore.viewer):
//
//	VALKEY_GCP_INSTANCE=projects/P/locations/R/instances/I go run ./cmd/live_matrix
//
// Explicit path, with no Memorystore API call: leave VALKEY_GCP_INSTANCE unset and set
// MEMORYSTORE_TEST_DISCOVERY_ENDPOINT (cluster) or VALKEY_GCP_PRIMARY_ENDPOINT and optionally
// VALKEY_GCP_READER_ENDPOINT (cluster-disabled), plus VALKEY_GCP_AUTH_MODE (iam, token or
// disabled) and VALKEY_GCP_TLS_CA_FILE when in-transit encryption is on. For an instance with
// in-transit encryption disabled, set VALKEY_GCP_TLS_MODE=disabled: valkeygcp refuses to send
// IAM or Token Auth credentials without TLS unless TLS is turned off explicitly.
//
//	MEMORYSTORE_TEST_DISCOVERY_ENDPOINT=10.0.0.15:6379 VALKEY_GCP_AUTH_MODE=iam \
//	  VALKEY_GCP_TLS_CA_FILE=server-ca.pem go run ./cmd/live_matrix
//
// Both paths read VALKEY_GCP_TOKEN_SECRET, the Secret Manager version that holds the
// TOKEN_AUTH token (projects/P/secrets/S/versions/V), and VALKEY_GCP_TOKEN_USERNAME, its
// user (empty for the default user). VALKEY_GCP_USERNAME_STRATEGY=principal-email makes IAM
// AUTH send the principal's email as the username instead of "default", for an instance
// whose ACL policy is keyed by email.
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

	// PING every node: each one is its own connection, with its own AUTH and, with TLS, a
	// certificate check against the node's IP address.
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
		// valkeygcp reads the endpoints from the instance. An InitAddress set here would
		// override them, so the endpoint variables are only read without an instance, which
		// keeps the two paths apart.
		opts = append(opts, valkeygcp.WithInstance(instance))
	} else {
		// WithTopology states the endpoint's cluster mode, which WithInstance would read
		// from the instance. With TopologyCluster, NewClient fails instead of quietly using
		// a single-node client when cluster mode doesn't work, for example because an ACL
		// rule denies CLUSTER SHARDS.
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
		// VALKEY_GCP_USERNAME_STRATEGY=principal-email means IAM, both is an error and
		// neither means no auth.
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
