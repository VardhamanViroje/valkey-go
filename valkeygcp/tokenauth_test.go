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
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Token: "static-token"})
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
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Username: "app-user", Token: "t"})
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
	})
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
		OnCredentialError: func(err error) {
			mu.Lock()
			absorbed = append(absorbed, err)
			mu.Unlock()
		},
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
	})
	if err == nil || !strings.Contains(err.Error(), "initial token fetch") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("got %v", err)
	}
	if _, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Source: func(context.Context) (string, error) { return " \n", nil }}); err == nil {
		t.Fatal("a blank token must be rejected")
	}
	if _, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{}); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("no source: got %v", err)
	}
}

// T-TOK-6
func TestTokenAuth_SecretManagerTrimmed(t *testing.T) {
	orig := newSecretSource
	defer func() { newSecretSource = orig }()
	var gotVersion string
	newSecretSource = func(_ context.Context, version string) (func(context.Context) (string, error), error) {
		gotVersion = version
		return func(context.Context) (string, error) { return "secret-token\n", nil }, nil
	}
	const version = "projects/p/secrets/valkey-default-token/versions/latest"
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{SecretVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); creds.Password != "secret-token" {
		t.Fatalf("got %q, want the trimmed token", creds.Password)
	}
	if gotVersion != version {
		t.Errorf("read %q, want %q", gotVersion, version)
	}

	// Source overrides SecretVersion and Token.
	p, err = newTokenAuthProvider(context.Background(), TokenAuthOptions{
		SecretVersion: version, Token: "static",
		Source: func(context.Context) (string, error) { return "from-source", nil },
	})
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
	})
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
	})
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
	if err := WithTokenAuth(TokenAuthOptions{Token: "tok"})(context.Background(), &opt); err != nil || opt.AuthCredentialsFn == nil {
		t.Fatalf("WithTokenAuth: %v", err)
	}
	if err := WithTokenAuth(TokenAuthOptions{})(context.Background(), &valkey.ClientOption{}); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("got %v", err)
	}
}

// T-TOK-8: the constructor's ctx bounds the first read made by WithTokenAuth.
func TestWithTokenAuth_HonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewStandaloneClient(ctx, "127.0.0.1:0", "127.0.0.1:0", WithTokenAuth(TokenAuthOptions{
		Source: func(ctx context.Context) (string, error) {
			<-ctx.Done() // a Secret Manager read that never answers
			return "", ctx.Err()
		},
	}))
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "initial token fetch") {
		t.Fatalf("got %v, want the caller's deadline on the first read", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("setup took %v despite a 50ms deadline", d)
	}
}

// T-TOK-9: without a caller deadline the first read is still capped (setupTimeout), and
// reads on the connection path get tokenFetchTimeout.
func TestTokenAuth_ReadDeadlines(t *testing.T) {
	var deadlines []time.Duration
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{
		ReloadInterval: 2 * time.Millisecond, // re-read on the next AUTH
		Source: func(ctx context.Context) (string, error) {
			d, ok := ctx.Deadline()
			if !ok {
				return "", errors.New("read without a deadline")
			}
			deadlines = append(deadlines, time.Until(d))
			return "tok", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	authOnce(t, p)
	if len(deadlines) != 2 || deadlines[0] > setupTimeout || deadlines[0] <= tokenFetchTimeout || deadlines[1] > tokenFetchTimeout {
		t.Fatalf("read deadlines = %v, want ~%v (setup) then <= %v (connection path)", deadlines, setupTimeout, tokenFetchTimeout)
	}
}

// T-TOK-10: WithTokenAuth reports read errors hidden behind the last-known-good token.
func TestWithTokenAuth_OnCredentialError(t *testing.T) {
	var fail atomic.Bool
	var absorbed atomic.Int32
	var opt valkey.ClientOption
	err := WithTokenAuth(TokenAuthOptions{
		ReloadInterval: 40 * time.Millisecond,
		Source: func(context.Context) (string, error) {
			if fail.Load() {
				return "", errors.New("secret manager unavailable")
			}
			return "good", nil
		},
		OnCredentialError: func(error) { absorbed.Add(1) },
	})(context.Background(), &opt)
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	time.Sleep(30 * time.Millisecond) // past the cache window (ReloadInterval/2)
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Password != "good" || absorbed.Load() != 1 {
		t.Fatalf("creds = %+v, %v; OnCredentialError calls = %d, want the last token and 1 call", creds, err, absorbed.Load())
	}
}

// T-TOK-11: one Secret Manager client serves every provider; a failed creation isn't cached.
func TestSharedSecretReader(t *testing.T) {
	origNew := newSecretManagerReader
	secretMu.Lock()
	origReader := secretReader
	secretReader = nil
	secretMu.Unlock()
	t.Cleanup(func() {
		newSecretManagerReader = origNew
		secretMu.Lock()
		secretReader = origReader
		secretMu.Unlock()
	})
	created, fail := 0, true
	newSecretManagerReader = func(context.Context) (func(context.Context, string) (string, error), error) {
		created++ // called under secretMu
		if fail {
			return nil, errors.New("no credentials")
		}
		return func(_ context.Context, version string) (string, error) { return "tok-" + version, nil }, nil
	}
	if _, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{SecretVersion: "v1"}); err == nil || !strings.Contains(err.Error(), "secret manager client") {
		t.Fatalf("got %v, want the client creation error", err)
	}
	fail = false
	for _, version := range []string{"v1", "v2", "v1"} {
		p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{SecretVersion: version})
		if err != nil {
			t.Fatal(err)
		}
		if got := authOnce(t, p).Password; got != "tok-"+version {
			t.Fatalf("%s: got %q", version, got)
		}
	}
	if created != 2 {
		t.Fatalf("Secret Manager clients created = %d, want 2 (one failed, then one shared)", created)
	}
}
