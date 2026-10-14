package valkeygcp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

func authOnce(t *testing.T, p *tokenAuthProvider) valkey.AuthCredentials {
	t.Helper()
	creds, err := p.AuthCredentialsFn()(valkey.AuthCredentialsContext{})
	if err != nil {
		t.Fatal(err)
	}
	return creds
}

// T-TOK-1
func TestTokenAuth_StaticDefaultUser(t *testing.T) {
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Token: "static-token"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := authOnce(t, p)
	// An empty Username makes valkey-go send HELLO 3 AUTH default <token> (pipe.go).
	if creds.Username != "" || creds.Password != "static-token" {
		t.Fatalf("creds = %+v", creds)
	}
	if d := time.Until(creds.RefreshAfter); d <= 0 || d > DefaultTokenReloadInterval {
		t.Errorf("RefreshAfter in %v, want within the default reload interval", d)
	}
}

// T-TOK-2
func TestTokenAuth_NamedUser(t *testing.T) {
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Username: "app-user", Token: "t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); creds.Username != "app-user" || creds.Password != "t" {
		t.Fatalf("creds = %+v", creds)
	}
}

// T-TOK-3
func TestTokenAuth_ReloadAfterCacheWindow(t *testing.T) {
	const reload = 200 * time.Millisecond
	var calls atomic.Int32
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		ReloadInterval: reload,
		Source: func(context.Context) (string, error) {
			if calls.Add(1) == 1 {
				return "v1", nil
			}
			return "v2", nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); creds.Password != "v1" {
		t.Fatalf("inside the cache window: got %q", creds.Password)
	}
	time.Sleep(reload/2 + 20*time.Millisecond) // past the cache window (reload/2)
	before := time.Now()
	creds := authOnce(t, p)
	if creds.Password != "v2" {
		t.Fatalf("after the cache window: got %q", creds.Password)
	}
	if d := creds.RefreshAfter.Sub(before); d < reload*9/10 || d > reload+50*time.Millisecond {
		t.Errorf("RefreshAfter in %v, want 90-100%% of %v", d, reload)
	}
}

// T-TOK-4
func TestTokenAuth_LastKnownGood(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	var absorbed []error
	var mu sync.Mutex
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		ReloadInterval: 200 * time.Millisecond,
		Source: func(context.Context) (string, error) {
			calls.Add(1)
			if fail.Load() {
				return "", errors.New("secret manager unavailable")
			}
			return "good", nil
		},
	}, func(err error) {
		mu.Lock()
		absorbed = append(absorbed, err)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	time.Sleep(120 * time.Millisecond) // past the 100ms cache window
	if creds := authOnce(t, p); creds.Password != "good" {
		t.Fatalf("got %q, want the last-known-good token", creds.Password)
	}
	mu.Lock()
	n := len(absorbed)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("OnCredentialError called %d times, want 1", n)
	}
	// The failed read is not retried on every new connection.
	before := calls.Load()
	for range 10 {
		authOnce(t, p)
	}
	if calls.Load() != before {
		t.Errorf("source called %d more times during the retry back-off", calls.Load()-before)
	}
}

// T-TOK-5
func TestTokenAuth_InitialFetchFails(t *testing.T) {
	_, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		Source: func(context.Context) (string, error) { return "", errors.New("permission denied") },
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "initial token fetch") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("got %v", err)
	}
	if _, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Source: func(context.Context) (string, error) { return " \n", nil }}, nil); err == nil {
		t.Fatal("a blank token must be rejected")
	}
	if _, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{}, nil); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("no source: got %v", err)
	}
}

// T-TOK-6
func TestTokenAuth_SecretManagerTrimmed(t *testing.T) {
	orig := newSecretSource
	defer func() { newSecretSource = orig }()
	var gotVersion string
	var closed bool
	newSecretSource = func(_ context.Context, version string) (func(context.Context) (string, error), func() error, error) {
		gotVersion = version
		return func(context.Context) (string, error) { return "secret-token\n", nil }, func() error { closed = true; return nil }, nil
	}
	const version = "projects/p/secrets/valkey-default-token/versions/latest"
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{SecretVersion: version}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); creds.Password != "secret-token" {
		t.Fatalf("got %q, want the trimmed token", creds.Password)
	}
	if gotVersion != version {
		t.Errorf("read %q, want %q", gotVersion, version)
	}
	p.close()
	if !closed {
		t.Error("Secret Manager client not closed")
	}

	// Source overrides SecretVersion and Token.
	p, err = newTokenAuthProvider(context.Background(), TokenAuthOptions{
		SecretVersion: version, Token: "static",
		Source: func(context.Context) (string, error) { return "from-source", nil },
	}, nil)
	if err != nil || authOnce(t, p).Password != "from-source" {
		t.Fatalf("Source precedence: %v", err)
	}
}

// T-TOK-7
func TestTokenAuth_OneFetchForManyDials(t *testing.T) {
	var calls atomic.Int32
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		Source: func(context.Context) (string, error) {
			calls.Add(1)
			return "tok", nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fn := p.AuthCredentialsFn()
	var wg sync.WaitGroup
	for range 1000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if creds, err := fn(valkey.AuthCredentialsContext{}); err != nil || creds.Password != "tok" {
				t.Errorf("creds = %+v, %v", creds, err)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("upstream fetches = %d, want exactly 1", n)
	}
}

func TestTokenAuth_ReloadDisabled(t *testing.T) {
	var calls atomic.Int32
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		ReloadInterval: -1,
		Source: func(context.Context) (string, error) {
			calls.Add(1)
			return "tok", nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); !creds.RefreshAfter.IsZero() {
		t.Errorf("RefreshAfter = %v, want zero with reload disabled", creds.RefreshAfter)
	}
	if calls.Load() != 1 {
		t.Errorf("source called %d times, want 1", calls.Load())
	}
}

func TestWithTokenAuth(t *testing.T) {
	var opt valkey.ClientOption
	if err := WithTokenAuth(TokenAuthOptions{Token: "tok"})(&opt); err != nil || opt.AuthCredentialsFn == nil {
		t.Fatalf("WithTokenAuth: %v", err)
	}
	if err := WithTokenAuth(TokenAuthOptions{})(&valkey.ClientOption{}); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("got %v", err)
	}
}
