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

// DefaultTokenReloadInterval is how often Token Auth re-reads the token by default, so a
// rotated token reaches live connections.
const DefaultTokenReloadInterval = 5 * time.Minute

// tokenFetchTimeout limits one token read made while connecting or re-authenticating.
const tokenFetchTimeout = 5 * time.Second

var errNoTokenSource = errors.New("valkeygcp: WithTokenAuth needs TokenAuthOptions.SecretVersion, Token or Source")

// TokenAuthOptions configures Token Auth, for instances whose authorization mode is Token
// Auth: clients log in with an auth token that Memorystore issues to a token auth user. Set
// one token source: SecretVersion (recommended), Token or Source.
type TokenAuthOptions struct {
	// Username is the token auth user. Empty means the default user: valkey-go then sends
	// AUTH default <token>.
	Username string
	// SecretVersion is the Secret Manager secret version that holds the token, for example
	// "projects/P/secrets/valkey-token/versions/latest". It is read with Application Default
	// Credentials, whose identity needs roles/secretmanager.secretAccessor on the secret.
	SecretVersion string
	// Token is a fixed token, for local development. A fixed token can't follow a rotation.
	Token string
	// Source reads the token your own way; it takes precedence over SecretVersion and Token.
	// It must return when ctx ends: reads while connecting or re-authenticating get a 5s
	// deadline, and the first read gets NewClient's ctx, capped at 15s.
	Source func(ctx context.Context) (string, error)
	// ReloadInterval is how often live connections re-AUTH with the current token, so a
	// rotated token reaches them. The token itself is read at most once per half interval,
	// however many connections ask for it. Zero means DefaultTokenReloadInterval; negative
	// turns reloading off.
	ReloadInterval time.Duration
	// OnCredentialError receives the token read errors that valkeygcp works around instead
	// of returning: when a re-read fails, connections keep the last token that worked, and
	// the read is retried within 30s. Use it for logs and metrics.
	OnCredentialError func(error)
}

// tokenAuthProvider hands out the Token Auth credentials of one NewClient or
// ResolveClientOption call.
type tokenAuthProvider struct {
	opt       TokenAuthOptions
	fetch     func(ctx context.Context) (string, error)
	mu        sync.Mutex
	last      string    // the last token read successfully
	nextFetch time.Time // when the token may be read again
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

// newSecretManagerReader creates the Secret Manager client behind sharedSecretReader, with
// Application Default Credentials. It is a variable so tests can replace it.
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
// client to add one would hide its concrete type from valkey-go's helpers. The client is
// created on first use and kept for the life of the process; a failed creation is retried
// on the next call.
var (
	secretMu     sync.Mutex
	secretReader func(ctx context.Context, version string) (string, error)
)

// sharedSecretReader returns the process-wide Secret Manager reader, creating it on first
// use.
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

// newTokenAuthProvider builds the Token Auth provider and reads the token once, so a wrong
// secret fails NewClient instead of the first connection. ctx bounds that first read, which
// also stops after 15s when ctx has no earlier deadline.
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
	if _, err := p.token(setupCtx); err != nil { // fail before the first connection
		return nil, fmt.Errorf("valkeygcp: initial token fetch: %w", err)
	}
	return p, nil
}

// token returns the current token. A read error that the last token covers goes to
// OnCredentialError, called outside the lock because the callback may log or block.
func (p *tokenAuthProvider) token(ctx context.Context) (string, error) {
	tok, absorbed, err := p.cachedToken(ctx)
	if absorbed != nil && p.opt.OnCredentialError != nil {
		p.opt.OnCredentialError(absorbed)
	}
	return tok, err
}

// cachedToken returns the token, reading it again at most once per half reload interval.
// absorbed is a read error covered by the last token that worked.
func (p *tokenAuthProvider) cachedToken(ctx context.Context) (tok string, absorbed, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.last != "" && (p.opt.ReloadInterval < 0 || now.Before(p.nextFetch)) {
		return p.last, nil, nil // no secret read for every new connection
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
		// Keep the last token: during a rotation the old and the new token both work for a
		// while. Retry within 30s instead of on every new connection.
		p.nextFetch = now.Add(min(credentialRetry, p.opt.ReloadInterval/2))
		return p.last, err, nil
	}
	p.last, p.nextFetch = tok, now.Add(p.opt.ReloadInterval/2)
	return tok, nil, nil
}

// AuthCredentialsFn returns the valkey.ClientOption.AuthCredentialsFn of this provider:
// valkey-go calls it for every new connection and at every scheduled re-AUTH.
func (p *tokenAuthProvider) AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		// valkey-go passes no context here, so each read gets its own deadline.
		ctx, cancel := context.WithTimeout(context.Background(), tokenFetchTimeout)
		defer cancel()
		tok, err := p.token(ctx)
		if err != nil {
			return valkey.AuthCredentials{}, err
		}
		creds := valkey.AuthCredentials{Username: p.opt.Username, Password: tok} // empty Username: AUTH default <token>
		if p.opt.ReloadInterval > 0 {
			creds.RefreshAfter = time.Now().Add(jitter(p.opt.ReloadInterval))
		}
		return creds, nil
	}
}

// WithTokenAuth authenticates with Token Auth, using the token from opt's source. NewClient's
// ctx bounds the first token read. It can't be combined with WithIAMOptions or
// WithDefaultIAM: an instance uses either IAM or Token Auth.
func WithTokenAuth(opt TokenAuthOptions) Option {
	return func(c *config) { c.token = &opt }
}
