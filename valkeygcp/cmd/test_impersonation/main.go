// Command test_impersonation checks service account impersonation: it builds an IAM token
// provider with IAMAuthOptions.ImpersonateSA set to the service account in
// VALKEY_GCP_IMPERSONATE_SA, fetches one token for it and prints the token's first 15
// characters. Impersonation lets a workload authenticate as another service account, for
// example one that may connect to an instance in another project.
//
// The identity that impersonates is Application Default Credentials; it needs
// roles/iam.serviceAccountTokenCreator on the target service account. The program doesn't
// connect to Memorystore. Run it from the valkeygcp directory:
//
//	VALKEY_GCP_IMPERSONATE_SA=sa@proj.iam.gserviceaccount.com go run ./cmd/test_impersonation
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx := context.Background()
	targetSA := os.Getenv("VALKEY_GCP_IMPERSONATE_SA")
	if targetSA == "" {
		panic("VALKEY_GCP_IMPERSONATE_SA environment variable is required")
	}

	provider, err := valkeygcp.NewGCPTokenProvider(ctx, valkeygcp.IAMAuthOptions{
		ImpersonateSA: targetSA,
	})
	if err != nil {
		panic(err)
	}

	tok, err := provider.Token(ctx)
	if err != nil {
		panic(fmt.Sprintf("Impersonation failed: %v", err))
	}

	fmt.Printf("✅ Successfully acquired impersonated token for: %s\n", targetSA)
	prefixLen := 15
	if len(tok.AccessToken) < prefixLen {
		prefixLen = len(tok.AccessToken)
	}
	fmt.Printf("Token Prefix: %s...\n", tok.AccessToken[:prefixLen])
}
