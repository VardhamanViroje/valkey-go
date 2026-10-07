package valkeygcp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
)

// mockTokenSource simulates a Google OAuth2 token source with configurable expiry and call tracking.
type mockTokenSource struct {
	mu         sync.Mutex
	calls      int64
	tokens     []*oauth2.Token
	defaultTok *oauth2.Token
	err        error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	atomic.AddInt64(&m.calls, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	if len(m.tokens) > 0 {
		tok := m.tokens[0]
		m.tokens = m.tokens[1:]
		return tok, nil
	}
	if m.defaultTok != nil {
		return m.defaultTok, nil
	}
	return &oauth2.Token{
		AccessToken: "mock-token-" + time.Now().Format(time.RFC3339Nano),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}, nil
}

func (m *mockTokenSource) CallCount() int64 {
	return atomic.LoadInt64(&m.calls)
}

// 1. Basic Token Acquisition and Credential Formatting
func TestNewGCPTokenProvider_CustomTokenSource(t *testing.T) {
	ctx := context.Background()
	expectedToken := &oauth2.Token{
		AccessToken: "initial-secret-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	mock := &mockTokenSource{defaultTok: expectedToken}

	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		Username:          "custom-user",
		RefreshBuffer:     10 * time.Minute,
		CustomTokenSource: mock,
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	tok, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("unexpected error fetching token: %v", err)
	}
	if tok.AccessToken != expectedToken.AccessToken {
		t.Errorf("got token %q, want %q", tok.AccessToken, expectedToken.AccessToken)
	}

	// Verify AuthCredentialsFn
	authFn := provider.AuthCredentialsFn()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("unexpected error in AuthCredentialsFn: %v", err)
	}
	if creds.Username != "custom-user" {
		t.Errorf("got username %q, want custom-user", creds.Username)
	}
	if creds.Password != expectedToken.AccessToken {
		t.Errorf("got password %q, want %q", creds.Password, expectedToken.AccessToken)
	}

	// Verify RefreshAfter is approximately Expiry - 10m
	expectedRefresh := expectedToken.Expiry.Add(-10 * time.Minute)
	diff := creds.RefreshAfter.Sub(expectedRefresh)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("got RefreshAfter %v, want ~%v", creds.RefreshAfter, expectedRefresh)
	}
}

// 2. Defect C1 Halving Loop Regression Test
func TestDefectC1_HalvingLoopPrevention(t *testing.T) {
	ctx := context.Background()

	// Token 1: Expires in 4 minutes (which is inside the 5-minute buffer)
	token1 := &oauth2.Token{
		AccessToken: "token-expiring-soon",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(4 * time.Minute),
	}
	// Token 2: Refreshed token expiring in 1 hour
	token2 := &oauth2.Token{
		AccessToken: "token-refreshed",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	mock := &mockTokenSource{
		tokens: []*oauth2.Token{token1, token2},
	}

	// Create provider with 5-minute buffer
	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		RefreshBuffer:     5 * time.Minute,
		CustomTokenSource: mock,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// First call consumes token1
	tok1, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("first token call failed: %v", err)
	}
	if tok1.AccessToken != "token-expiring-soon" {
		t.Errorf("got token %q, want token-expiring-soon", tok1.AccessToken)
	}
	if mock.CallCount() != 1 {
		t.Errorf("expected 1 underlying call, got %d", mock.CallCount())
	}

	// Under standard ReuseTokenSource, calling Token() now would see 4 minutes remaining (>10s)
	// and return the same token1 without calling mock.
	// But with ReuseTokenSourceWithExpiry(5m), remaining time (4m) < buffer (5m),
	// so it MUST fetch token2 immediately!
	tok2, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("second token call failed: %v", err)
	}
	if tok2.AccessToken != "token-refreshed" {
		t.Errorf("C1 Fix Failed! Got cached token %q instead of refreshed token %q", tok2.AccessToken, "token-refreshed")
	}
	if mock.CallCount() != 2 {
		t.Errorf("expected 2 underlying calls due to eager refresh, got %d", mock.CallCount())
	}
}

// 3. Near-Expiry and Expired Token Fallback Logic
func TestAuthCredentialsFn_NearExpiryFallback(t *testing.T) {
	ctx := context.Background()

	// Case 1: Token expiring in 2 minutes with a 5-minute buffer
	nearExpiryToken := &oauth2.Token{
		AccessToken: "near-expiry-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(2 * time.Minute),
	}
	mock := &mockTokenSource{defaultTok: nearExpiryToken}

	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		RefreshBuffer:     5 * time.Minute,
		CustomTokenSource: mock,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	authFn := provider.AuthCredentialsFn()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("authFn failed: %v", err)
	}

	// Remaining time is ~2m, so refreshAt should be scheduled at ~1m in the future (remaining / 2)
	timeUntilRefresh := time.Until(creds.RefreshAfter)
	if timeUntilRefresh < 45*time.Second || timeUntilRefresh > 75*time.Second {
		t.Errorf("got timeUntilRefresh %v, want ~1m (half remaining)", timeUntilRefresh)
	}

	// Case 2: Already expired token -> should fall back to +10s
	expiredToken := &oauth2.Token{
		AccessToken: "expired-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-1 * time.Minute),
	}
	mockExpired := &mockTokenSource{defaultTok: expiredToken}
	providerExpired, _ := NewGCPTokenProvider(ctx, IAMAuthOptions{
		RefreshBuffer:     5 * time.Minute,
		CustomTokenSource: mockExpired,
	})
	credsExpired, err := providerExpired.AuthCredentialsFn()(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("authFn on expired token failed: %v", err)
	}
	timeUntilExpiredRefresh := time.Until(credsExpired.RefreshAfter)
	if timeUntilExpiredRefresh < 8*time.Second || timeUntilExpiredRefresh > 12*time.Second {
		t.Errorf("got timeUntilExpiredRefresh %v, want ~10s", timeUntilExpiredRefresh)
	}
}

// 4. Invalid JSON Credentials Validation
func TestNewGCPTokenProvider_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	_, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		CredentialsJSON: []byte(`{ invalid json`),
	})
	if err == nil {
		t.Fatal("expected error with invalid JSON, got nil")
	}
}

// 5. Concurrency and Race Safety
func TestAuthCredentials_Concurrency(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "concurrent-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}
	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		CustomTokenSource: mock,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	authFn := provider.AuthCredentialsFn()

	const goroutines = 20
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, err := provider.Token(ctx)
				if err != nil {
					t.Errorf("concurrent Token() failed: %v", err)
				}
				creds, err := authFn(valkey.AuthCredentialsContext{})
				if err != nil {
					t.Errorf("concurrent AuthCredentialsFn() failed: %v", err)
				}
				if creds.Username != DefaultIAMUsername {
					t.Errorf("unexpected username %q", creds.Username)
				}
			}
		}()
	}

	wg.Wait()
}

// 6. ClientOption Wiring
func TestWithIAMOptions_ClientOptionWiring(t *testing.T) {
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "wired-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	opt := valkey.ClientOption{}
	gcpOpt := WithIAMOptions(IAMAuthOptions{
		Username:          "memorystore-user",
		CustomTokenSource: mock,
	})

	if err := gcpOpt(&opt); err != nil {
		t.Fatalf("WithIAMOptions failed: %v", err)
	}

	if opt.AuthCredentialsFn == nil {
		t.Fatal("expected AuthCredentialsFn to be configured on ClientOption, got nil")
	}

	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("AuthCredentialsFn execution failed: %v", err)
	}
	if creds.Username != "memorystore-user" {
		t.Errorf("got username %q, want memorystore-user", creds.Username)
	}
	if creds.Password != "wired-token" {
		t.Errorf("got password %q, want wired-token", creds.Password)
	}
}

// 7. Token Error Propagation
func TestAuthCredentialsFn_TokenError(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		err: errors.New("network failure fetching oauth2 token"),
	}

	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		CustomTokenSource: mock,
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	authFn := provider.AuthCredentialsFn()
	_, err = authFn(valkey.AuthCredentialsContext{})
	if err == nil {
		t.Fatal("expected error from authFn when token acquisition fails, got nil")
	}
}

// 8. WithIAMOptions Error Handling
func TestWithIAMOptions_Error(t *testing.T) {
	opt := valkey.ClientOption{}
	gcpOpt := WithIAMOptions(IAMAuthOptions{
		CredentialsJSON: []byte(`{ invalid-json`),
	})

	err := gcpOpt(&opt)
	if err == nil {
		t.Fatal("expected error from WithIAMOptions with invalid JSON, got nil")
	}
}

// 9. Default Options Verification
func TestNewGCPTokenProvider_Defaults(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "default-opts-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	provider, err := NewGCPTokenProvider(ctx, IAMAuthOptions{
		CustomTokenSource: mock,
		// Leaving Username, RefreshBuffer, Scopes empty to trigger defaults
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	authFn := provider.AuthCredentialsFn()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("unexpected error in AuthCredentialsFn: %v", err)
	}
	if creds.Username != DefaultIAMUsername {
		t.Errorf("got username %q, want %q", creds.Username, DefaultIAMUsername)
	}
}
