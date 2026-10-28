package valkeygcp

import (
	"cmp"
	"context"
	"errors"
	"net"
	"os"
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

// tokenOption resolves a ClientOption with only WithTokenAuth(opt), without connecting.
func tokenOption(t *testing.T, opt TokenAuthOptions) (valkey.ClientOption, error) {
	t.Helper()
	return ResolveClientOption(context.Background(), valkey.ClientOption{InitAddress: []string{"127.0.0.1:0"}}, WithTokenAuth(opt))
}

func TestTokenAuth_StaticDefaultUser(t *testing.T) {
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Token: "static-token"})
	if err != nil {
		t.Fatal(err)
	}
	creds := authOnce(t, p)
	// An empty Username makes valkey-go send HELLO 3 AUTH default <token>.
	if creds.Username != "" || creds.Password != "static-token" {
		t.Fatalf("creds = %+v", creds)
	}
	if d := time.Until(creds.RefreshAfter); d <= 0 || d > DefaultTokenReloadInterval {
		t.Errorf("RefreshAfter in %v, want within the default reload interval", d)
	}
}

func TestTokenAuth_NamedUser(t *testing.T) {
	p, err := newTokenAuthProvider(context.Background(), TokenAuthOptions{Username: "app-user", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if creds := authOnce(t, p); creds.Username != "app-user" || creds.Password != "t" {
		t.Fatalf("creds = %+v", creds)
	}
}

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
		t.Fatalf("got %q, want the last token that worked", creds.Password)
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

	// Source takes precedence over SecretVersion and Token.
	p, err = newTokenAuthProvider(context.Background(), TokenAuthOptions{
		SecretVersion: version, Token: "static",
		Source: func(context.Context) (string, error) { return "from-source", nil },
	})
	if err != nil || authOnce(t, p).Password != "from-source" {
		t.Fatalf("Source precedence: %v", err)
	}
}

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

// Without a caller deadline the first read is still capped (setupTimeout), and reads while
// connecting or re-authenticating get tokenFetchTimeout.
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

// One Secret Manager client serves every provider; a failed creation isn't cached.
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

func TestWithTokenAuth(t *testing.T) {
	opt, err := tokenOption(t, TokenAuthOptions{Token: "tok"})
	if err != nil || opt.AuthCredentialsFn == nil {
		t.Fatalf("WithTokenAuth: %v", err)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != "" || creds.Password != "tok" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
	if opt.Dialer.Timeout != defaultDialTimeout || opt.RetryDelay == nil {
		t.Errorf("Memorystore defaults not filled in: dial timeout %v, retry delay set %v", opt.Dialer.Timeout, opt.RetryDelay != nil)
	}
	if _, err := tokenOption(t, TokenAuthOptions{}); !errors.Is(err, errNoTokenSource) {
		t.Fatalf("got %v", err)
	}
}

// NewClient's ctx bounds the first token read made for WithTokenAuth.
func TestWithTokenAuth_HonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewClient(ctx, valkey.ClientOption{InitAddress: []string{"127.0.0.1:0"}}, WithTokenAuth(TokenAuthOptions{
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

// WithTokenAuth reports read errors covered by the last token that worked.
func TestWithTokenAuth_OnCredentialError(t *testing.T) {
	var fail atomic.Bool
	var absorbed atomic.Int32
	opt, err := tokenOption(t, TokenAuthOptions{
		ReloadInterval: 40 * time.Millisecond,
		Source: func(context.Context) (string, error) {
			if fail.Load() {
				return "", errors.New("secret manager unavailable")
			}
			return "good", nil
		},
		OnCredentialError: func(error) { absorbed.Add(1) },
	})
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

// WithTokenAuth can't be combined with IAM or with credentials on the ClientOption, and the
// last WithTokenAuth wins.
func TestWithTokenAuth_Conflicts(t *testing.T) {
	ctx := context.Background()
	addr := []string{"127.0.0.1:0"}
	tok := WithTokenAuth(TokenAuthOptions{Token: "tok"})

	for _, opts := range [][]Option{{WithDefaultIAM(), tok}, {tok, WithIAMOptions(IAMAuthOptions{})}} {
		if _, err := ResolveClientOption(ctx, valkey.ClientOption{InitAddress: addr}, opts...); err == nil || !strings.Contains(err.Error(), "can't be combined") {
			t.Errorf("IAM and Token Auth together: got %v", err)
		}
	}
	for field, option := range map[string]valkey.ClientOption{
		"Password": {InitAddress: addr, Password: "p"},
		"Username": {InitAddress: addr, Username: "u"},
		"AuthCredentialsFn": {InitAddress: addr, AuthCredentialsFn: func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
			return valkey.AuthCredentials{}, nil
		}},
	} {
		if _, err := ResolveClientOption(ctx, option, tok); err == nil || !strings.Contains(err.Error(), "ClientOption."+field+" conflicts with WithTokenAuth") {
			t.Errorf("%s: got %v", field, err)
		}
	}
	opt, err := ResolveClientOption(ctx, valkey.ClientOption{InitAddress: addr},
		WithTokenAuth(TokenAuthOptions{Token: "first"}), WithTokenAuth(TokenAuthOptions{Token: "last"}))
	if err != nil {
		t.Fatal(err)
	}
	if creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{}); err != nil || creds.Password != "last" {
		t.Fatalf("creds = %+v, %v; want the last WithTokenAuth", creds, err)
	}
}

// TestTokenAuth_LiveRotation rotates a token on a real Valkey while a client is connected:
// the live connection re-AUTHs with the new token and stays the same connection, and a new
// connection gets the new token. It needs a local Valkey whose default user has no password
// (docker compose up -d valkey), at 127.0.0.1:6379 or VALKEYGCP_TEST_ADDR, and is skipped
// without one. It creates and deletes its own ACL user.
func TestTokenAuth_LiveRotation(t *testing.T) {
	addr := cmp.Or(os.Getenv("VALKEYGCP_TEST_ADDR"), "127.0.0.1:6379")
	admin, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:       []string{addr},
		ForceSingleClient: true,
		DisableCache:      true,
		Dialer:            net.Dialer{Timeout: 300 * time.Millisecond},
	})
	if err != nil {
		t.Skipf("no local Valkey without a password at %s: %v", addr, err)
	}
	t.Cleanup(admin.Close)
	ctx := context.Background()
	const user = "valkeygcp-token-test"
	acl := func(args ...string) {
		t.Helper()
		if err := admin.Do(ctx, admin.B().Arbitrary("ACL").Args(args...).Build()).Error(); err != nil {
			t.Fatalf("ACL %v: %v", args, err)
		}
	}
	acl("SETUSER", user, "reset", "on", ">token-1", "~*", "+@all")
	t.Cleanup(func() {
		_ = admin.Do(context.Background(), admin.B().Arbitrary("ACL").Args("DELUSER", user).Build()).Error()
	})

	const reload = 400 * time.Millisecond
	var current atomic.Value
	current.Store("token-1")
	opt, err := ResolveClientOption(ctx, valkey.ClientOption{
		InitAddress:       []string{addr},
		ForceSingleClient: true,
		PipelineMultiplex: -1, // one connection, so CLIENT ID tells whether it was replaced
		DisableCache:      true,
	}, WithTokenAuth(TokenAuthOptions{
		Username:       user,
		ReloadInterval: reload,
		Source:         func(context.Context) (string, error) { return current.Load().(string), nil },
	}))
	if err != nil {
		t.Fatal(err)
	}
	client, err := valkey.NewClient(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	id, err := client.Do(ctx, client.B().ClientId().Build()).AsInt64()
	if err != nil {
		t.Fatal(err)
	}
	if who, err := client.Do(ctx, client.B().AclWhoami().Build()).ToString(); err != nil || who != user {
		t.Fatalf("ACL WHOAMI = %q, %v; want %q", who, err, user)
	}

	// Rotate: the user accepts both tokens for a while, and the source hands out the new one.
	acl("SETUSER", user, ">token-2")
	current.Store("token-2")
	time.Sleep(4 * reload) // the cache re-reads within reload/2, and the connection re-AUTHs within reload
	// Retire the old token. A re-AUTH that still sent it would now fail and close the connection.
	acl("SETUSER", user, "<token-1")
	time.Sleep(2 * reload)

	if got, err := client.Do(ctx, client.B().ClientId().Build()).AsInt64(); err != nil || got != id {
		t.Fatalf("CLIENT ID = %d, %v; want %d: the connection was replaced, so a re-AUTH failed", got, err, id)
	}
	if err := client.Do(ctx, client.B().Set().Key("valkeygcp:token-rotation").Value("ok").Build()).Error(); err != nil {
		t.Fatalf("SET after the rotation: %v", err)
	}
	fresh, err := valkey.NewClient(opt) // a new connection, with the same provider
	if err != nil {
		t.Fatalf("new connection after the rotation: %v", err)
	}
	fresh.Close()
}
