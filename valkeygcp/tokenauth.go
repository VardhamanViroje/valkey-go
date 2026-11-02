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
	"google.golang.org/api/option"
)

// DefaultTokenReloadInterval is how often a TOKEN_AUTH token is re-read by default.
const DefaultTokenReloadInterval = 5 * time.Minute

// tokenFetchTimeout bounds one token read for a new connection or a re-AUTH.
const tokenFetchTimeout = 5 * time.Second

var errNoTokenSource = errors.New("valkeygcp: TOKEN_AUTH needs WithTokenAuth with TokenAuthOptions.SecretVersion, Token or Source")

// TokenAuthOptions configures TOKEN_AUTH (basic token-based authentication).
type TokenAuthOptions struct {
	// Username is the token-auth user; "" means the default user (AUTH <token>).
	Username string
	// SecretVersion holds the token in Secret Manager (recommended), e.g.
	// "projects/P/secrets/valkey-default-token/versions/latest". A regional secret
	// ("projects/P/locations/L/secrets/S/versions/V") is read through its regional endpoint,
	// secretmanager.L.rep.googleapis.com.
	SecretVersion string
	// Token is a static token (local development only).
	Token string
	// Source is a custom fetcher; it overrides SecretVersion and Token. It must return when
	// ctx ends: reads for new connections and re-AUTHs get a 5s deadline, and the first
	// read, during setup, gets the caller's deadline (at most 15s).
	Source func(ctx context.Context) (string, error)
	// ReloadInterval controls how often the token is re-read so rotated tokens reach
	// live connections (re-AUTH). Default 5m; negative disables reload.
	ReloadInterval time.Duration
	// OnCredentialError receives the token read errors that valkeygcp works around by
	// reusing the last token read, so a failed read doesn't close connections. When nil, the
	// OnCredentialError option is used.
	OnCredentialError func(error)
	// OnAuth receives an AuthEvent each time credentials are handed to valkey-go, for logs
	// and metrics. It runs while a connection is being set up, so it must return quickly.
	// When nil, the OnAuth option is used.
	OnAuth func(AuthEvent)
}

// tokenAuthProvider hands out the Token Auth token. It caches the token and reads it again
// at most once per half ReloadInterval, so new connections don't each read the secret.
type tokenAuthProvider struct {
	opt       TokenAuthOptions
	fetch     func(ctx context.Context) (string, error) // reads the token from its source
	plaintext bool                                      // true when the connections don't use TLS (AuthEvent.Plaintext)
	mu        sync.Mutex
	last      string    // the last token read successfully, used when a read fails
	nextFetch time.Time // when to read the token again
}

// newSecretSource returns a reader for one Secret Manager secret version. It is a variable
// so tests can replace Secret Manager.
var newSecretSource = func(ctx context.Context, version string) (func(context.Context) (string, error), error) {
	read, err := sharedSecretReader(ctx, secretLocation(version))
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (string, error) { return read(ctx, version) }, nil
}

// newSecretManagerReader creates the Secret Manager client behind sharedSecretReader for one
// location ("" for global secrets); tests replace it. Regional secrets are only served by
// their regional endpoint. Reading a secret needs secretmanager.versions.access.
var newSecretManagerReader = func(ctx context.Context, location string) (func(ctx context.Context, version string) (string, error), error) {
	var opts []option.ClientOption
	if location != "" {
		opts = append(opts, option.WithEndpoint(regionalSecretEndpoint(location)))
	}
	sm, err := secretmanager.NewClient(ctx, opts...)
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

// regionalSecretEndpoint is the Secret Manager endpoint for regional secrets in location.
func regionalSecretEndpoint(location string) string {
	return fmt.Sprintf("secretmanager.%s.rep.googleapis.com:443", location)
}

// secretLocation returns L for a regional secret version
// "projects/P/locations/L/secrets/S/versions/V", and "" for a global one.
func secretLocation(version string) string {
	p := strings.Split(version, "/")
	if len(p) == 8 && p[0] == "projects" && p[2] == "locations" && p[4] == "secrets" && p[6] == "versions" && p[3] != "" {
		return p[3]
	}
	return ""
}

// One Secret Manager client per location serves every Token Auth provider in the process. A
// client per provider would leak, because valkey.Client has no close hook, and wrapping the
// returned client to add one would hide its concrete type from valkey-go's helpers, such as
// valkey.MGet and valkey.MSet, which check that type. A client is created on first use and
// kept for the life of the process; a failed creation is retried on the next call.
var (
	secretMu      sync.Mutex
	secretReaders = map[string]func(ctx context.Context, version string) (string, error){}
)

// sharedSecretReader returns the process-wide secret reader for location, creating it on
// first use.
func sharedSecretReader(ctx context.Context, location string) (func(context.Context, string) (string, error), error) {
	secretMu.Lock()
	defer secretMu.Unlock()
	if read, ok := secretReaders[location]; ok {
		return read, nil
	}
	// The client outlives ctx, so it must not inherit ctx's cancellation.
	read, err := newSecretManagerReader(context.WithoutCancel(ctx), location)
	if err != nil {
		if location != "" {
			return nil, fmt.Errorf("valkeygcp: secret manager client for %s: %w", regionalSecretEndpoint(location), err)
		}
		return nil, fmt.Errorf("valkeygcp: secret manager client: %w", err)
	}
	secretReaders[location] = read
	return read, nil
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
	if _, _, err := p.token(setupCtx); err != nil { // fail fast before the first dial
		return nil, fmt.Errorf("valkeygcp: initial token fetch: %w", err)
	}
	return p, nil
}

// token returns the token, and whether it is the last token read, used because a read
// failed. It reports that failure to OnCredentialError.
func (p *tokenAuthProvider) token(ctx context.Context) (string, bool, error) {
	tok, absorbed, err := p.cachedToken(ctx)
	if absorbed != nil && p.opt.OnCredentialError != nil {
		p.opt.OnCredentialError(absorbed) // outside the lock: the callback may log or block
	}
	return tok, absorbed != nil, err
}

// cachedToken returns the token, re-reading it at most once per half reload interval.
// absorbed is a read error hidden by returning the last token read.
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
		// Keep serving the last token (both tokens stay valid during a rotation window) and
		// retry later rather than on every new connection.
		p.nextFetch = now.Add(min(credentialRetry, p.opt.ReloadInterval/2))
		return p.last, err, nil
	}
	p.last, p.nextFetch = tok, now.Add(p.opt.ReloadInterval/2)
	return tok, nil, nil
}

// AuthCredentialsFn returns the valkey.ClientOption.AuthCredentialsFn of this provider. Each
// call hands valkey-go the username and token, schedules the next re-AUTH so rotated tokens
// reach live connections, and reports an AuthEvent to OnAuth.
func (p *tokenAuthProvider) AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(c valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		creds, fallback, err := p.credentials()
		if p.opt.OnAuth != nil {
			p.opt.OnAuth(authEvent(c, p.opt.Username, creds, fallback, p.plaintext, err))
		}
		return creds, err
	}
}

// credentials returns the AUTH credentials and whether the last token read was used because
// a read failed.
func (p *tokenAuthProvider) credentials() (valkey.AuthCredentials, bool, error) {
	// AuthCredentialsContext carries no context (dials and timer-driven refreshes have no
	// caller to take one from), so each read gets its own deadline.
	ctx, cancel := context.WithTimeout(context.Background(), tokenFetchTimeout)
	defer cancel()
	tok, fallback, err := p.token(ctx)
	if err != nil {
		return valkey.AuthCredentials{}, false, err
	}
	creds := valkey.AuthCredentials{Username: p.opt.Username, Password: tok} // "" user => AUTH default <token>
	if p.opt.ReloadInterval > 0 {
		creds.RefreshAfter = time.Now().Add(jitter(p.opt.ReloadInterval))
	}
	return creds, fallback, nil
}

// WithTokenAuth authenticates with a TOKEN_AUTH token from opt. NewClient reads the token once
// during setup, bounded by its ctx, so a bad secret fails NewClient instead of the first dial.
func WithTokenAuth(opt TokenAuthOptions) Option {
	return func(c *config) { c.token = &opt }
}
