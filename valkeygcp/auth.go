package valkeygcp

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
)

// Defaults applied when the matching IAMAuthOptions field is left empty.
const (
	DefaultCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	DefaultRefreshBuffer      = 5 * time.Minute
	DefaultIAMUsername        = "default"
	// DefaultTokenFetchTimeout caps one upstream IAM token fetch (IAMAuthOptions.FetchTimeout).
	DefaultTokenFetchTimeout = 10 * time.Second
)

// credentialRetry is how soon a failed token refresh is retried while the last-known-good
// token is served (U6). jitter spreads it over 27-30s.
const credentialRetry = 30 * time.Second

// IAMAuthOptions configures the GCP IAM OAuth2 token provider.
type IAMAuthOptions struct {
	Username          string
	RefreshBuffer     time.Duration
	CustomTokenSource oauth2.TokenSource
	Scopes            []string
	CredentialsJSON   []byte
	ImpersonateSA     string
	Delegates         []string

	// UsernameStrategy picks the AUTH username when Username is empty (U4).
	UsernameStrategy UsernameStrategy
	// ImpersonateLifetime is the lifetime of impersonated tokens (impersonate.CredentialsConfig.Lifetime).
	// Zero means 1h. The maximum is 12h; more than 1h needs the org policy
	// constraints/iam.allowServiceAccountCredentialLifetimeExtension. Must exceed RefreshBuffer.
	ImpersonateLifetime time.Duration
	// DisableProactiveReauth turns off re-AUTH on live connections (Q2): every new connection
	// still gets a fresh token, but RefreshAfter stays zero.
	DisableProactiveReauth bool
	// MaxAuthPerSecond paces token-backed AUTHs per process (U5). 0 disables pacing.
	MaxAuthPerSecond float64
	// OnCredentialError receives token fetch errors absorbed by the last-known-good logic (U6).
	// NewClient copies AuthOptions.OnCredentialError here when this field is nil.
	OnCredentialError func(error)
	// FetchTimeout caps one upstream token fetch, so a hung token endpoint can't block new
	// connections. A timed-out fetch is handled like any failed fetch (U6). Zero means
	// DefaultTokenFetchTimeout; negative disables the cap.
	FetchTimeout time.Duration
}

// GCPTokenProvider manages the retrieval, caching, and lifecycle of IAM OAuth2 access tokens.
type GCPTokenProvider interface {
	Token(ctx context.Context) (*oauth2.Token, error)
	AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error)
}

type tokenProvider struct {
	source        oauth2.TokenSource
	refreshBuffer time.Duration
	username      string
	lastGood      atomic.Pointer[oauth2.Token]
	disableReauth bool
	limiter       *authLimiter
	onErr         func(error)
}

// impersonateTokenSource is impersonate.CredentialsTokenSource; tests replace it.
var impersonateTokenSource = impersonate.CredentialsTokenSource

// NewGCPTokenProvider creates an IAM token manager with eager refresh margin to prevent halving loops (C1).
//
// ctx bounds the one-off setup (credential discovery, impersonation, the principal-email
// lookup), capped at 15s when it has no earlier deadline. Token refreshes don't use it.
func NewGCPTokenProvider(ctx context.Context, opt IAMAuthOptions) (GCPTokenProvider, error) {
	if opt.RefreshBuffer <= 0 {
		opt.RefreshBuffer = DefaultRefreshBuffer
	}
	if len(opt.Scopes) == 0 {
		opt.Scopes = []string{DefaultCloudPlatformScope}
	}
	if opt.FetchTimeout == 0 {
		opt.FetchTimeout = DefaultTokenFetchTimeout
	}
	if opt.ImpersonateLifetime < 0 || (opt.ImpersonateLifetime > 0 && opt.ImpersonateLifetime <= opt.RefreshBuffer) {
		return nil, fmt.Errorf("valkeygcp: ImpersonateLifetime (%v) must be longer than RefreshBuffer (%v)", opt.ImpersonateLifetime, opt.RefreshBuffer)
	}

	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	// Token sources refresh for as long as the client lives, so they must not inherit ctx's
	// cancellation (a NewClient timeout would otherwise break every later refresh). The setup
	// itself still stops when setupCtx ends: callWithContext stops waiting for it.
	srcCtx := context.WithoutCancel(ctx)
	base, err := callWithContext(setupCtx, "credential setup", func() (baseCreds, error) {
		return newBaseCreds(srcCtx, opt)
	})
	if err != nil {
		return nil, err
	}

	username, err := resolveUsername(setupCtx, opt, base.json)
	if err != nil {
		return nil, err
	}

	p := &tokenProvider{
		// Fix C1: Wrap source with ReuseTokenSourceWithExpiry to prevent redundant halving loop.
		// The fetch timeout sits underneath, so it caps upstream fetches, not cache hits.
		source:        oauth2.ReuseTokenSourceWithExpiry(nil, withFetchTimeout(base.source, opt.FetchTimeout), opt.RefreshBuffer),
		refreshBuffer: opt.RefreshBuffer,
		username:      username,
		disableReauth: opt.DisableProactiveReauth,
		onErr:         opt.OnCredentialError,
	}
	if opt.MaxAuthPerSecond > 0 {
		interval := min(float64(time.Second)/opt.MaxAuthPerSecond, float64(24*time.Hour)) // clamp: no int64 overflow
		p.limiter = &authLimiter{interval: time.Duration(interval)}
	}
	return p, nil
}

// baseCreds is the upstream token source and, when known, the credentials JSON behind it.
type baseCreds struct {
	source oauth2.TokenSource
	json   []byte // feeds the principal-email lookup (U4)
}

// newBaseCreds builds the upstream token source. ctx is kept by the source for later
// refreshes, so the caller passes a context without cancellation.
func newBaseCreds(ctx context.Context, opt IAMAuthOptions) (baseCreds, error) {
	switch {
	case opt.CustomTokenSource != nil:
		return baseCreds{source: opt.CustomTokenSource, json: opt.CredentialsJSON}, nil
	case opt.ImpersonateSA != "":
		// Gap G6: Cross-project Service Account Impersonation
		ts, err := newImpersonatedSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: opt.ImpersonateSA,
			Scopes:          opt.Scopes,
			Delegates:       opt.Delegates,
			Lifetime:        opt.ImpersonateLifetime,
		})
		if err != nil {
			return baseCreds{}, fmt.Errorf("valkeygcp: impersonation token source failed: %w", err)
		}
		return baseCreds{source: ts}, nil
	case len(opt.CredentialsJSON) > 0:
		// CredentialsFromJSONWithType instead of the deprecated CredentialsFromJSON (V10).
		creds, err := google.CredentialsFromJSONWithType(ctx, opt.CredentialsJSON, credTypeFromJSON(opt.CredentialsJSON), opt.Scopes...)
		if err != nil {
			return baseCreds{}, fmt.Errorf("valkeygcp: invalid credentials JSON: %w", err)
		}
		return baseCreds{source: creds.TokenSource, json: opt.CredentialsJSON}, nil
	default:
		creds, err := google.FindDefaultCredentials(ctx, opt.Scopes...)
		if err != nil {
			return baseCreds{}, fmt.Errorf("valkeygcp: Application Default Credentials not found: %w", err)
		}
		return baseCreds{source: creds.TokenSource, json: creds.JSON}, nil
	}
}

// Token returns the current token, fetching a new one inside the refresh buffer. ctx bounds
// how long the caller waits; the upstream fetch is also capped by FetchTimeout.
func (p *tokenProvider) Token(ctx context.Context) (*oauth2.Token, error) {
	return callWithContext(ctx, "token fetch", func() (*oauth2.Token, error) {
		tok, err := p.source.Token()
		if err == nil {
			p.lastGood.Store(tok) // also when the caller has stopped waiting
		}
		return tok, err
	})
}

func (p *tokenProvider) AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		p.limiter.wait()             // U5: no-op unless MaxAuthPerSecond > 0
		tok, err := p.source.Token() // C1: ReuseTokenSourceWithExpiry
		now := time.Now()
		if err != nil {
			return p.tolerate(now, err)
		}
		p.lastGood.Store(tok)
		creds := valkey.AuthCredentials{Username: p.username, Password: tok.AccessToken}
		// A zero Expiry means the token never expires, so there is nothing to refresh.
		if !p.disableReauth && !tok.Expiry.IsZero() {
			creds.RefreshAfter = refreshTime(now, tok.Expiry, p.refreshBuffer)
		}
		return creds, nil
	}
}

// tolerate applies the refresh-failure rules (U6). refreshAuth closes the connection when
// AuthCredentialsFn fails (pipe.go refreshAuth -> p._exit), so a short token-source outage
// must not surface as an error while a live connection can keep working.
func (p *tokenProvider) tolerate(now time.Time, err error) (valkey.AuthCredentials, error) {
	last := p.lastGood.Load()
	lastValid := last != nil && (last.Expiry.IsZero() || last.Expiry.After(now))
	// Never succeeded: surface the real error. With DisableProactiveReauth the provider only
	// runs on new dials, so an expired token has no live connection to protect either.
	if last == nil || (p.disableReauth && !lastValid) {
		return valkey.AuthCredentials{}, fmt.Errorf("valkeygcp: token acquisition failed: %w", err)
	}
	if p.onErr != nil {
		p.onErr(err)
	}
	if p.disableReauth { // dial-only mode: serve the valid token without arming a refresh timer
		return valkey.AuthCredentials{Username: p.username, Password: last.AccessToken}, nil
	}
	retry := now.Add(jitter(credentialRetry))
	if lastValid { // U6: still valid, keep using it and retry soon
		return valkey.AuthCredentials{Username: p.username, Password: last.AccessToken, RefreshAfter: retry}, nil
	}
	// U6: expired. Empty credentials make refreshAuth skip AUTH (the connection stays
	// authenticated, V3); a brand-new dial fails with NOAUTH until the source recovers.
	return valkey.AuthCredentials{RefreshAfter: retry}, nil
}

// refreshTime schedules the re-AUTH INSIDE the C1 buffer, so the cache always hands out a
// new token at that moment, spread over the first half of the buffer (U5). Jittering
// earlier than Expiry-buffer would re-AUTH with the same cached token.
func refreshTime(now, expiry time.Time, buffer time.Duration) time.Time {
	start := expiry.Add(-buffer)
	if now.Before(start) {
		return start.Add(time.Duration(rand.Int64N(int64(buffer/2) + 1)))
	}
	if remaining := expiry.Sub(now); remaining > 0 {
		return now.Add(remaining / 2) // existing near-expiry fallback
	}
	return now.Add(10 * time.Second)
}

// jitter returns d minus up to 10%, never more than d (shared with the Token Auth provider).
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d - time.Duration(rand.Int64N(int64(d)/10+1))
}

// authLimiter paces token-backed AUTHs per process (U5). A nil limiter is a no-op.
type authLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func (l *authLimiter) wait() {
	if l == nil || l.interval <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	sleep := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	time.Sleep(sleep)
}

// newImpersonatedSource builds the impersonated token source (G6). With a Lifetime set,
// impersonate.CredentialsTokenSource returns a static source that never refreshes, so it is
// wrapped to mint a new token whenever the C1 cache asks for one.
func newImpersonatedSource(ctx context.Context, cfg impersonate.CredentialsConfig) (oauth2.TokenSource, error) {
	ts, err := impersonateTokenSource(ctx, cfg)
	if err != nil || cfg.Lifetime == 0 {
		return ts, err
	}
	return &lifetimeSource{ctx: ctx, cfg: cfg, first: ts}, nil
}

// lifetimeSource refreshes impersonated tokens that use a custom lifetime.
type lifetimeSource struct {
	ctx   context.Context
	cfg   impersonate.CredentialsConfig
	mu    sync.Mutex
	first oauth2.TokenSource // the static source from construction, used once
}

func (s *lifetimeSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	first := s.first
	s.first = nil
	s.mu.Unlock()
	if first != nil {
		return first.Token()
	}
	ts, err := impersonateTokenSource(s.ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	return ts.Token()
}

// callWithContext runs fn and stops waiting when ctx ends, for calls that take no context
// or keep the one they get for later refreshes. fn then finishes in the background and its
// result is dropped.
func callWithContext[T any](ctx context.Context, what string, fn func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1) // buffered: an abandoned fn never blocks
	go func() {
		v, err := fn()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("valkeygcp: %s: %w", what, ctx.Err())
	}
}

// withFetchTimeout caps each upstream fetch of src (IAMAuthOptions.FetchTimeout). A negative
// timeout returns src unchanged.
func withFetchTimeout(src oauth2.TokenSource, timeout time.Duration) oauth2.TokenSource {
	if timeout < 0 {
		return src
	}
	return &timeoutSource{src: src, timeout: timeout}
}

// timeoutSource stops waiting for an upstream fetch after timeout, so a hung token endpoint
// can't block new connections (nor, through the C1 cache's lock, every other caller).
// oauth2.TokenSource can't be cancelled, so a timed-out fetch keeps running in the
// background. Later calls wait for that fetch instead of starting another until it is
// 3*timeout old, so a hung endpoint costs at most one goroutine per 3*timeout.
type timeoutSource struct {
	src     oauth2.TokenSource
	timeout time.Duration

	mu  sync.Mutex
	cur *tokenFetch // the latest fetch, shared while it runs
}

type tokenFetch struct {
	start time.Time
	done  chan struct{} // closed when tok and err are set
	tok   *oauth2.Token
	err   error
}

func (f *tokenFetch) finished() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

func (s *timeoutSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	f := s.cur
	if f == nil || f.finished() || time.Since(f.start) > 3*s.timeout {
		f = &tokenFetch{start: time.Now(), done: make(chan struct{})}
		s.cur = f
		go func() {
			f.tok, f.err = s.src.Token()
			close(f.done)
		}()
	}
	s.mu.Unlock()

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	select {
	case <-f.done:
		return f.tok, f.err
	case <-timer.C:
		return nil, fmt.Errorf("token fetch timed out after %v", s.timeout)
	}
}

// WithDefaultIAM configures the client to authenticate using Application Default Credentials.
func WithDefaultIAM() GCPOption {
	return WithIAMOptions(IAMAuthOptions{})
}

// WithIAMOptions configures custom IAM authentication options. The constructor's ctx bounds
// the provider's setup (see NewGCPTokenProvider).
func WithIAMOptions(iamOpt IAMAuthOptions) GCPOption {
	return func(ctx context.Context, opt *valkey.ClientOption) error {
		provider, err := NewGCPTokenProvider(ctx, iamOpt)
		if err != nil {
			return err
		}
		opt.AuthCredentialsFn = provider.AuthCredentialsFn()
		return nil
	}
}
