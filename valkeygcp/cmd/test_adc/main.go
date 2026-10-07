package main

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx := context.Background()
	provider, err := valkeygcp.NewGCPTokenProvider(ctx, valkeygcp.IAMAuthOptions{})
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize ADC provider: %v", err))
	}

	tok, err := provider.Token(ctx)
	if err != nil {
		panic(fmt.Sprintf("Failed to acquire token from ADC: %v", err))
	}

	fmt.Printf("✅ Successfully acquired Google OAuth2 Access Token!\n")
	prefixLen := 15
	if len(tok.AccessToken) < prefixLen {
		prefixLen = len(tok.AccessToken)
	}
	fmt.Printf("Token Prefix: %s...\n", tok.AccessToken[:prefixLen])
	fmt.Printf("Token Type:   %s\n", tok.TokenType)
	fmt.Printf("Expiration:   %s (in %v)\n", tok.Expiry.Format(time.RFC3339), time.Until(tok.Expiry).Round(time.Second))
}
