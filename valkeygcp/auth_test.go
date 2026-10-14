package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
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

	// Verify RefreshAfter lands inside the C1 buffer window [Expiry - 10m, Expiry - 5m] (U5 jitter)
	windowStart := expectedToken.Expiry.Add(-10 * time.Minute)
	windowEnd := expectedToken.Expiry.Add(-5 * time.Minute)
	if creds.RefreshAfter.Before(windowStart) || creds.RefreshAfter.After(windowEnd) {
		t.Errorf("got RefreshAfter %v, want within [%v, %v]", creds.RefreshAfter, windowStart, windowEnd)
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

	if err := gcpOpt(context.Background(), &opt); err != nil {
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

	err := gcpOpt(context.Background(), &opt)
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

// 10. Refresh tolerance (U6): the provider must not make refreshAuth close healthy connections.

// T-U6-1
func TestRefreshTolerance_CachedTokenValid(t *testing.T) {
	var fail atomic.Bool
	src := tokenSourceFunc(func() (*oauth2.Token, error) {
		if fail.Load() {
			return nil, errors.New("metadata server unreachable")
		}
		// Inside the 5m buffer, so the C1 cache asks the source again on the next call.
		return &oauth2.Token{AccessToken: "cached", Expiry: time.Now().Add(3 * time.Minute)}, nil
	})
	var absorbed atomic.Int32
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: src,
		OnCredentialError: func(error) { absorbed.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	if _, err := authFn(valkey.AuthCredentialsContext{}); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	before := time.Now()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("refresh failure surfaced as an error (would close the connection): %v", err)
	}
	if creds.Username != DefaultIAMUsername || creds.Password != "cached" {
		t.Errorf("creds = %+v, want the cached token", creds)
	}
	if d := creds.RefreshAfter.Sub(before); d < 27*time.Second || d > 30*time.Second+100*time.Millisecond {
		t.Errorf("retry in %v, want 27-30s", d)
	}
	if absorbed.Load() != 1 {
		t.Errorf("OnCredentialError called %d times, want 1", absorbed.Load())
	}
}

// T-U6-2
func TestRefreshTolerance_CachedTokenExpired(t *testing.T) {
	mock := &mockTokenSource{tokens: []*oauth2.Token{{AccessToken: "expired", Expiry: time.Now().Add(-time.Minute)}}}
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: mock})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	if _, err := authFn(valkey.AuthCredentialsContext{}); err != nil {
		t.Fatal(err)
	}
	mock.mu.Lock()
	mock.err = errors.New("sts unavailable")
	mock.mu.Unlock()
	before := time.Now()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatalf("got error %v, want empty credentials", err)
	}
	if creds.Username != "" || creds.Password != "" {
		t.Errorf("creds = %+v, want empty (refreshAuth then skips AUTH)", creds)
	}
	if d := creds.RefreshAfter.Sub(before); d < 27*time.Second || d > 30*time.Second+100*time.Millisecond {
		t.Errorf("retry in %v, want 27-30s", d)
	}
}

// T-U6-3
func TestRefreshTolerance_NeverSucceeded(t *testing.T) {
	var absorbed atomic.Int32
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: &mockTokenSource{err: errors.New("no credentials")},
		OnCredentialError: func(error) { absorbed.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.AuthCredentialsFn()(valkey.AuthCredentialsContext{}); err == nil {
		t.Fatal("want the real error when no token was ever fetched")
	}
	if absorbed.Load() != 0 {
		t.Error("a surfaced error must not also go to OnCredentialError")
	}
}

// T-U6-4: needs the docker compose Valkey on 127.0.0.1:6379 (run by dockertest.sh in CI).
func TestRefreshTolerance_LiveConnection(t *testing.T) {
	const addr = "127.0.0.1:6379"
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	if c, err := dialer.DialContext(context.Background(), "tcp", addr); err != nil {
		t.Skipf("no local Valkey at %s: %v", addr, err)
	} else {
		_ = c.Close()
	}
	var fail atomic.Bool
	var issued atomic.Int32
	src := tokenSourceFunc(func() (*oauth2.Token, error) {
		if fail.Load() {
			return nil, errors.New("metadata server unreachable")
		}
		return &oauth2.Token{AccessToken: fmt.Sprintf("tok-%d", issued.Add(1)), Expiry: time.Now().Add(3 * time.Second)}, nil
	})
	var absorbed atomic.Int32
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: src,
		RefreshBuffer:     2 * time.Second, // first re-AUTH 1-2s after the dial
		OnCredentialError: func(error) { absorbed.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// One connection, so CLIENT ID tells whether it was replaced. The default user is
	// nopass, so AUTH default <token> succeeds like an accepted IAM token.
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:       []string{addr},
		ForceSingleClient: true,
		PipelineMultiplex: -1,
		DisableCache:      true,
		AuthCredentialsFn: provider.AuthCredentialsFn(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	id, err := client.Do(ctx, client.B().ClientId().Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true) // the token source goes down before the first refresh
	deadline := time.Now().Add(5 * time.Second)
	for absorbed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if absorbed.Load() == 0 {
		t.Fatal("the refresh never ran")
	}
	after, err := client.Do(ctx, client.B().ClientId().Build()).AsInt64()
	if err != nil {
		t.Fatalf("command failed after the refresh failure: %v", err)
	}
	if after != id {
		t.Fatalf("connection was replaced (CLIENT ID %d -> %d)", id, after)
	}
	if err := client.Do(ctx, client.B().Set().Key("valkeygcp:u6").Value("ok").Build()).Error(); err != nil {
		t.Fatal(err)
	}
}

// T-U6-5
func TestRefreshTolerance_RefreshTimeWindow(t *testing.T) {
	now := time.Now()
	expiry := now.Add(time.Hour)
	const buffer = 5 * time.Minute
	for range 1000 {
		at := refreshTime(now, expiry, buffer)
		if at.Before(expiry.Add(-buffer)) || at.After(expiry.Add(-buffer/2)) {
			t.Fatalf("refresh at Expiry-%v, want within [Expiry-%v, Expiry-%v]", expiry.Sub(at), buffer, buffer/2)
		}
	}
	if got := refreshTime(now, now.Add(2*time.Minute), buffer).Sub(now); got != time.Minute {
		t.Errorf("near expiry: %v, want half the remaining time", got)
	}
	if got := refreshTime(now, now.Add(-time.Minute), buffer).Sub(now); got != 10*time.Second {
		t.Errorf("expired: %v, want 10s", got)
	}
	for range 1000 {
		if j := jitter(30 * time.Second); j < 27*time.Second || j > 30*time.Second {
			t.Fatalf("jitter = %v", j)
		}
	}
	if jitter(0) != 0 || jitter(-time.Second) != -time.Second {
		t.Error("jitter must pass non-positive durations through")
	}
}

// T-U6-6
func TestRefreshTolerance_DisableProactiveReauth(t *testing.T) {
	var fail atomic.Bool
	expiry := time.Now().Add(3 * time.Minute)
	src := tokenSourceFunc(func() (*oauth2.Token, error) {
		if fail.Load() {
			return nil, errors.New("down")
		}
		return &oauth2.Token{AccessToken: "t", Expiry: expiry}, nil
	})
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: src, DisableProactiveReauth: true})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "t" || !creds.RefreshAfter.IsZero() {
		t.Fatalf("creds = %+v, %v; want zero RefreshAfter", creds, err)
	}
	// Dial-only mode: a valid cached token is still served, without arming a timer...
	fail.Store(true)
	creds, err = authFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "t" || !creds.RefreshAfter.IsZero() {
		t.Fatalf("cached: %+v, %v", creds, err)
	}
	// ...but an expired one fails the dial with the real error.
	provider.(*tokenProvider).lastGood.Store(&oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Second)})
	if _, err := authFn(valkey.AuthCredentialsContext{}); err == nil {
		t.Fatal("expired cached token in dial-only mode must fail")
	}
}

func TestAuthCredentials_NonExpiringToken(t *testing.T) {
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "forever"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := provider.AuthCredentialsFn()(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "forever" || !creds.RefreshAfter.IsZero() {
		t.Fatalf("creds = %+v, %v; a token without expiry needs no refresh", creds, err)
	}
}

// 11. Connection-rate pacing (U5)
func TestMaxAuthPerSecond(t *testing.T) {
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: &mockTokenSource{},
		MaxAuthPerSecond:  20, // one AUTH per 50ms
	})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	start := time.Now()
	for range 4 {
		if _, err := authFn(valkey.AuthCredentialsContext{}); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 140*time.Millisecond {
		t.Errorf("4 AUTHs took %v, want >= 150ms at 20/s", elapsed)
	}
	var nilLimiter *authLimiter
	nilLimiter.wait() // no-op, must not panic
	if p := provider.(*tokenProvider); p.limiter == nil || p.limiter.interval != 50*time.Millisecond {
		t.Errorf("limiter = %+v", p.limiter)
	}
	unpaced, _ := NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: &mockTokenSource{}})
	if unpaced.(*tokenProvider).limiter != nil {
		t.Error("MaxAuthPerSecond 0 must not create a limiter")
	}
}

// 12. Impersonation with a custom token lifetime (G6)
func TestImpersonateLifetime(t *testing.T) {
	orig := impersonateTokenSource
	defer func() { impersonateTokenSource = orig }()
	var calls atomic.Int32
	var got impersonate.CredentialsConfig
	impersonateTokenSource = func(_ context.Context, cfg impersonate.CredentialsConfig, _ ...option.ClientOption) (oauth2.TokenSource, error) {
		n := calls.Add(1)
		got = cfg
		// What impersonate returns when Lifetime is set: a static source that never refreshes.
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: fmt.Sprintf("imp-%d", n), Expiry: time.Now().Add(time.Minute)}), nil
	}
	const sa = "reader@db-proj.iam.gserviceaccount.com"
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		ImpersonateSA:       sa,
		Delegates:           []string{"hop@p.iam.gserviceaccount.com"},
		ImpersonateLifetime: 2 * time.Hour,
		UsernameStrategy:    UsernamePrincipalEmail,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetPrincipal != sa || got.Lifetime != 2*time.Hour || len(got.Delegates) != 1 || got.Scopes[0] != DefaultCloudPlatformScope {
		t.Errorf("config = %+v", got)
	}
	for i, want := range []string{"imp-1", "imp-2"} {
		tok, err := provider.Token(context.Background())
		if err != nil || tok.AccessToken != want {
			t.Fatalf("token %d = %v, %v; want %s (refreshed)", i, tok, err, want)
		}
	}
	if creds, _ := provider.AuthCredentialsFn()(valkey.AuthCredentialsContext{}); creds.Username != sa {
		t.Errorf("username = %q, want the impersonated principal", creds.Username)
	}

	// Without a Lifetime the impersonate source refreshes itself and is used directly.
	calls.Store(0)
	provider, err = NewGCPTokenProvider(context.Background(), IAMAuthOptions{ImpersonateSA: sa})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = provider.Token(context.Background())
	_, _ = provider.Token(context.Background())
	if calls.Load() != 1 {
		t.Errorf("impersonate source built %d times, want 1", calls.Load())
	}

	for _, lifetime := range []time.Duration{-time.Minute, DefaultRefreshBuffer} {
		if _, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{ImpersonateSA: sa, ImpersonateLifetime: lifetime}); err == nil {
			t.Errorf("ImpersonateLifetime %v accepted", lifetime)
		}
	}
}

// 13. Context and timeouts: setup honors the caller's ctx; upstream fetches are capped.

// T-CTX-3: impersonation setup errors surface from the provider and the option.
func TestNewGCPTokenProvider_ImpersonationError(t *testing.T) {
	orig := impersonateTokenSource
	defer func() { impersonateTokenSource = orig }()
	impersonateTokenSource = func(context.Context, impersonate.CredentialsConfig, ...option.ClientOption) (oauth2.TokenSource, error) {
		return nil, errors.New("iam.serviceAccounts.getAccessToken denied")
	}
	opts := IAMAuthOptions{ImpersonateSA: "sa@p.iam.gserviceaccount.com"}
	if _, err := NewGCPTokenProvider(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "impersonation token source failed") || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("got %v, want the impersonation error", err)
	}
	var clientOpt valkey.ClientOption
	if err := WithIAMOptions(opts)(context.Background(), &clientOpt); err == nil || clientOpt.AuthCredentialsFn != nil {
		t.Fatalf("WithIAMOptions: err %v, AuthCredentialsFn set %v", err, clientOpt.AuthCredentialsFn != nil)
	}
}

// T-CTX-4: a hung credential setup (here the eager impersonation fetch used with
// ImpersonateLifetime) stops at the caller's deadline.
func TestNewGCPTokenProvider_SetupHonorsContext(t *testing.T) {
	orig := impersonateTokenSource
	entered, release := make(chan struct{}), make(chan struct{})
	impersonateTokenSource = func(context.Context, impersonate.CredentialsConfig, ...option.ClientOption) (oauth2.TokenSource, error) {
		close(entered)
		<-release // an IAM Credentials call that never answers
		return nil, errors.New("released")
	}
	t.Cleanup(func() {
		select { // the stub has read impersonateTokenSource before it is restored
		case <-entered:
		case <-time.After(5 * time.Second):
		}
		close(release)
		impersonateTokenSource = orig
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewGCPTokenProvider(ctx, IAMAuthOptions{ImpersonateSA: "sa@p.iam.gserviceaccount.com", ImpersonateLifetime: time.Hour})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "credential setup") {
		t.Fatalf("got %v, want the caller's deadline", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("setup took %v despite a 50ms deadline", d)
	}
}

// T-CTX-5: a hung token endpoint can't block a dial for longer than FetchTimeout, and later
// calls share the running fetch instead of piling up goroutines.
func TestFetchTimeout_HungSource(t *testing.T) {
	const timeout = 40 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int32
	hung := tokenSourceFunc(func() (*oauth2.Token, error) {
		calls.Add(1)
		<-release
		return nil, errors.New("released")
	})
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: hung, FetchTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	start := time.Now()
	if _, err := authFn(valkey.AuthCredentialsContext{}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v, want a fetch timeout (no token was ever fetched)", err)
	}
	if d := time.Since(start); d > timeout+time.Second {
		t.Fatalf("dial blocked for %v", d)
	}
	if _, err := authFn(valkey.AuthCredentialsContext{}); err == nil {
		t.Fatal("want a timeout while the fetch is still hung")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("upstream fetches = %d, want 1 while the first is still running", n)
	}
	time.Sleep(3 * timeout) // the running fetch now counts as stuck
	_, _ = authFn(valkey.AuthCredentialsContext{})
	if n := calls.Load(); n != 2 {
		t.Fatalf("upstream fetches = %d, want a fresh fetch after 3*FetchTimeout", n)
	}
	if _, ok := withFetchTimeout(hung, -1).(*timeoutSource); ok {
		t.Error("a negative FetchTimeout must disable the cap")
	}
}

// T-CTX-6: a fetch that times out after a success serves the last valid token (U6).
func TestFetchTimeout_FallsBackToLastGood(t *testing.T) {
	const timeout = 40 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int32
	src := tokenSourceFunc(func() (*oauth2.Token, error) {
		if calls.Add(1) == 1 {
			// Inside the refresh buffer, so the C1 cache fetches again on the next call.
			return &oauth2.Token{AccessToken: "first", Expiry: time.Now().Add(time.Minute)}, nil
		}
		<-release
		return nil, errors.New("released")
	})
	var absorbed atomic.Int32
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{
		CustomTokenSource: src,
		FetchTimeout:      timeout,
		OnCredentialError: func(error) { absorbed.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	authFn := provider.AuthCredentialsFn()
	if creds, err := authFn(valkey.AuthCredentialsContext{}); err != nil || creds.Password != "first" {
		t.Fatalf("first AUTH: %+v, %v", creds, err)
	}
	creds, err := authFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "first" || creds.RefreshAfter.IsZero() {
		t.Fatalf("after a timeout: %+v, %v; want the last valid token and a retry", creds, err)
	}
	if absorbed.Load() != 1 {
		t.Fatalf("OnCredentialError called %d times, want 1", absorbed.Load())
	}
}

// T-CTX-7: GCPTokenProvider.Token honors its ctx.
func TestTokenProvider_TokenHonorsContext(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hung := tokenSourceFunc(func() (*oauth2.Token, error) {
		<-release
		return nil, errors.New("released")
	})
	provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: hung, FetchTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := provider.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the caller's deadline", err)
	}
}
