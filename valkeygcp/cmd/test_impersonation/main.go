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
