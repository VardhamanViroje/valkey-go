package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/valkey-io/valkey-go"
)

// DefaultTokenReloadInterval is how often a TOKEN_AUTH token is re-read by default.
const DefaultTokenReloadInterval = 5 * time.Minute

// tokenFetchTimeout bounds one token read on the connection path.
const tokenFetchTimeout = 5 * time.Second

var errNoTokenSource = errors.New("valkeygcp: TOKEN_AUTH needs Auth.Token.SecretVersion, Token or Source")

// TokenAuthOptions configures TOKEN_AUTH (basic token-based authentication).
type TokenAuthOptions struct {
	// Username is the token-auth user; "" means the default user (AUTH <token>).
	Username string
	// SecretVersion holds the token in Secret Manager (recommended), e.g.
	// "projects/P/secrets/valkey-default-token/versions/latest".
	SecretVersion string
	// Token is a static token (local development only).
	Token string
	// Source is a custom fetcher; it overrides SecretVersion and Token. It must return when
	// ctx ends: reads on the connection path get a 5s deadline, and the first read during
	// setup gets the caller's deadline (at most 15s).
	Source func(ctx context.Context) (string, error)
	// ReloadInterval controls how often the token is re-read so rotated tokens reach
	// live connections (re-AUTH). Default 5m; negative disables reload.
	ReloadInterval time.Duration
	// OnCredentialError receives token read errors absorbed by the last-known-good logic
	// (U6). NewClient copies AuthOptions.OnCredentialError here when this field is nil.
	OnCredentialError func(error)
}

type tokenAuthProvider struct {
	opt       TokenAuthOptions
	fetch     func(ctx context.Context) (string, error)
	mu        sync.Mutex
	last      string    // last-known-good token (U6)
	nextFetch time.Time // cache: one upstream read per half reload interval
}

// newSecretSource returns a reader for one Secret Manager secret version. It is a variable
// so tests can replace Secret Manager.
var newSecretSource = func(ctx context.Context, version string) (func(context.Context) (string, error), error) {
	read, err := sharedSecretReader(ctx)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (string, error) { return read(ctx, version) }, nil
}

// newSecretManagerReader creates the Secret Manager client behind sharedSecretReader; tests
// replace it. Reading a secret needs secretmanager.versions.access.
var newSecretManagerReader = func(ctx context.Context) (func(ctx context.Context, version string) (string, error), error) {
	sm, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, version string) (string, error) {
		resp, err := sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: version})
		if err != nil {
			return "", err
		}
		return string(resp.GetPayload().GetData()), nil
	}, nil
}

// One Secret Manager client serves every Token Auth provider in the process. A client per
// provider would leak, because valkey.Client has no close hook, and wrapping the returned
// client to add one would hide its concrete type from valkey-go's helpers (helper.go
// switches on it for MGET/MSET and DisableCache). The client is created on first use and
// kept for the life of the process; a failed creation is retried on the next call.
var (
	secretMu     sync.Mutex
	secretReader func(ctx context.Context, version string) (string, error)
)

func sharedSecretReader(ctx context.Context) (func(context.Context, string) (string, error), error) {
	secretMu.Lock()
	defer secretMu.Unlock()
	if secretReader == nil {
		// The client outlives ctx, so it must not inherit ctx's cancellation.
		read, err := newSecretManagerReader(context.WithoutCancel(ctx))
		if err != nil {
			return nil, fmt.Errorf("valkeygcp: secret manager client: %w", err)
		}
		secretReader = read
	}
	return secretReader, nil
}

// newTokenAuthProvider builds the TOKEN_AUTH provider and reads the token once, so a bad
// secret fails setup instead of the first dial. ctx bounds that first read, capped at 15s
// when it has no earlier deadline.
func newTokenAuthProvider(ctx context.Context, opt TokenAuthOptions) (*tokenAuthProvider, error) {
	if opt.ReloadInterval == 0 {
		opt.ReloadInterval = DefaultTokenReloadInterval
	}
	p := &tokenAuthProvider{opt: opt}
	switch {
	case opt.Source != nil:
		p.fetch = opt.Source
	case opt.SecretVersion != "":
		fetch, err := newSecretSource(ctx, opt.SecretVersion)
		if err != nil {
			return nil, err
		}
		p.fetch = fetch
	case opt.Token != "":
		p.fetch = func(context.Context) (string, error) { return opt.Token, nil }
	default:
		return nil, errNoTokenSource
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	if _, err := p.token(setupCtx); err != nil { // fail fast before the first dial
		return nil, fmt.Errorf("valkeygcp: initial token fetch: %w", err)
	}
	return p, nil
}

func (p *tokenAuthProvider) token(ctx context.Context) (string, error) {
	tok, absorbed, err := p.cachedToken(ctx)
	if absorbed != nil && p.opt.OnCredentialError != nil {
		p.opt.OnCredentialError(absorbed) // outside the lock: the callback may log or block
	}
	return tok, err
}

// cachedToken returns the token, re-reading it at most once per half reload interval.
// absorbed is a fetch error hidden behind the last-known-good token (U6).
func (p *tokenAuthProvider) cachedToken(ctx context.Context) (tok string, absorbed, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.last != "" && (p.opt.ReloadInterval < 0 || now.Before(p.nextFetch)) {
		return p.last, nil, nil // no Secret Manager call per new connection
	}
	tok, err = p.fetch(ctx)
	tok = strings.TrimSpace(tok) // secret payloads often end with a newline
	if err == nil && tok == "" {
		err = errors.New("empty token")
	}
	if err != nil {
		if p.last == "" {
			return "", nil, err
		}
		// U6: keep serving the last token (both tokens stay valid during a rotation
		// window) and retry later rather than on every new connection.
		p.nextFetch = now.Add(min(credentialRetry, p.opt.ReloadInterval/2))
		return p.last, err, nil
	}
	p.last, p.nextFetch = tok, now.Add(p.opt.ReloadInterval/2)
	return tok, nil, nil
}

func (p *tokenAuthProvider) AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		// AuthCredentialsContext carries no context (dials and timer-driven refreshes have no
		// caller to take one from), so each read gets its own deadline.
		ctx, cancel := context.WithTimeout(context.Background(), tokenFetchTimeout)
		defer cancel()
		tok, err := p.token(ctx)
		if err != nil {
			return valkey.AuthCredentials{}, err
		}
		creds := valkey.AuthCredentials{Username: p.opt.Username, Password: tok} // "" user => AUTH default <token>
		if p.opt.ReloadInterval > 0 {
			creds.RefreshAfter = time.Now().Add(jitter(p.opt.ReloadInterval))
		}
		return creds, nil
	}
}

// WithTokenAuth wires TOKEN_AUTH into the low-level constructors. The constructor's ctx
// bounds the first token read.
func WithTokenAuth(opt TokenAuthOptions) GCPOption {
	return func(ctx context.Context, o *valkey.ClientOption) error {
		p, err := newTokenAuthProvider(ctx, opt)
		if err != nil {
			return err
		}
		o.AuthCredentialsFn = p.AuthCredentialsFn()
		return nil
	}
}
