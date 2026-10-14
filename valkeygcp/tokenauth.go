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
	// Source is a custom fetcher; it overrides SecretVersion and Token.
	Source func(ctx context.Context) (string, error)
	// ReloadInterval controls how often the token is re-read so rotated tokens reach
	// live connections (re-AUTH). Default 5m; negative disables reload.
	ReloadInterval time.Duration
}

type tokenAuthProvider struct {
	opt       TokenAuthOptions
	fetch     func(ctx context.Context) (string, error)
	closeFn   func() error // releases the Secret Manager client; nil for other sources
	onErr     func(error)
	mu        sync.Mutex
	last      string    // last-known-good token (U6)
	nextFetch time.Time // cache: one upstream read per half reload interval
}

// newSecretSource returns a reader for one Secret Manager secret version and a function
// that releases the client. It is a variable so tests can replace Secret Manager.
var newSecretSource = func(ctx context.Context, version string) (func(context.Context) (string, error), func() error, error) {
	// Needs secretmanager.versions.access. The client lives as long as the valkey client,
	// so it must not inherit ctx's cancellation.
	sm, err := secretmanager.NewClient(context.WithoutCancel(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("valkeygcp: secret manager client: %w", err)
	}
	fetch := func(ctx context.Context) (string, error) {
		resp, err := sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: version})
		if err != nil {
			return "", err
		}
		return string(resp.GetPayload().GetData()), nil
	}
	return fetch, sm.Close, nil
}

func newTokenAuthProvider(ctx context.Context, opt TokenAuthOptions, onErr func(error)) (*tokenAuthProvider, error) {
	if opt.ReloadInterval == 0 {
		opt.ReloadInterval = DefaultTokenReloadInterval
	}
	p := &tokenAuthProvider{opt: opt, onErr: onErr}
	switch {
	case opt.Source != nil:
		p.fetch = opt.Source
	case opt.SecretVersion != "":
		fetch, closeFn, err := newSecretSource(ctx, opt.SecretVersion)
		if err != nil {
			return nil, err
		}
		p.fetch, p.closeFn = fetch, closeFn
	case opt.Token != "":
		p.fetch = func(context.Context) (string, error) { return opt.Token, nil }
	default:
		return nil, errNoTokenSource
	}
	if _, err := p.token(ctx); err != nil { // fail fast before the first dial
		p.close()
		return nil, fmt.Errorf("valkeygcp: initial token fetch: %w", err)
	}
	return p, nil
}

// close releases the Secret Manager client, if any.
func (p *tokenAuthProvider) close() {
	if p.closeFn != nil {
		_ = p.closeFn()
	}
}

func (p *tokenAuthProvider) token(ctx context.Context) (string, error) {
	tok, absorbed, err := p.cachedToken(ctx)
	if absorbed != nil && p.onErr != nil {
		p.onErr(absorbed) // outside the lock: the callback may log or block
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

// WithTokenAuth wires TOKEN_AUTH into the low-level constructors.
func WithTokenAuth(opt TokenAuthOptions) GCPOption {
	return func(o *valkey.ClientOption) error {
		p, err := newTokenAuthProvider(context.Background(), opt, nil)
		if err != nil {
			return err
		}
		o.AuthCredentialsFn = p.AuthCredentialsFn()
		return nil
	}
}

