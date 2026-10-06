package valkeygcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
)

const (
	DefaultCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	DefaultRefreshBuffer      = 5 * time.Minute
	DefaultIAMUsername        = "default"
)

// GCPOption configures the valkey.ClientOption with Google Cloud specific parameters.
type GCPOption func(*valkey.ClientOption) error

// IAMAuthOptions configures the GCP IAM OAuth2 token provider.
type IAMAuthOptions struct {
	Username          string
	RefreshBuffer     time.Duration
	CustomTokenSource oauth2.TokenSource
	Scopes            []string
	CredentialsJSON   []byte
	ImpersonateSA     string
	Delegates         []string
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
	mu            sync.RWMutex
}

// NewGCPTokenProvider creates an IAM token manager with eager refresh margin to prevent halving loops (C1).
func NewGCPTokenProvider(ctx context.Context, opt IAMAuthOptions) (GCPTokenProvider, error) {
	if opt.Username == "" {
		opt.Username = DefaultIAMUsername
	}
	if opt.RefreshBuffer <= 0 {
		opt.RefreshBuffer = DefaultRefreshBuffer
	}
	if len(opt.Scopes) == 0 {
		opt.Scopes = []string{DefaultCloudPlatformScope}
	}

	var baseSource oauth2.TokenSource
	if opt.CustomTokenSource != nil {
		baseSource = opt.CustomTokenSource
	} else if opt.ImpersonateSA != "" {
		// Gap G6: Cross-project Service Account Impersonation
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: opt.ImpersonateSA,
			Scopes:          opt.Scopes,
			Delegates:       opt.Delegates,
		})
		if err != nil {
			return nil, fmt.Errorf("valkeygcp: impersonation token source failed: %w", err)
		}
		baseSource = ts
	} else if len(opt.CredentialsJSON) > 0 {
		creds, err := google.CredentialsFromJSON(ctx, opt.CredentialsJSON, opt.Scopes...)
		if err != nil {
			return nil, fmt.Errorf("valkeygcp: invalid credentials JSON: %w", err)
		}
		baseSource = creds.TokenSource
	} else {
		creds, err := google.FindDefaultCredentials(ctx, opt.Scopes...)
		if err != nil {
			return nil, fmt.Errorf("valkeygcp: Application Default Credentials not found: %w", err)
		}
		baseSource = creds.TokenSource
	}

	// Fix C1: Wrap source with ReuseTokenSourceWithExpiry to prevent redundant halving loop
	managedSource := oauth2.ReuseTokenSourceWithExpiry(nil, baseSource, opt.RefreshBuffer)

	return &tokenProvider{
		source:        managedSource,
		refreshBuffer: opt.RefreshBuffer,
		username:      opt.Username,
	}, nil
}

func (p *tokenProvider) Token(ctx context.Context) (*oauth2.Token, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.source.Token()
}

func (p *tokenProvider) AuthCredentialsFn() func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
	return func(actx valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
		tok, err := p.Token(context.Background())
		if err != nil {
			return valkey.AuthCredentials{}, fmt.Errorf("valkeygcp: token acquisition failed: %w", err)
		}

		refreshAt := tok.Expiry.Add(-p.refreshBuffer)
		if time.Now().After(refreshAt) {
			remaining := time.Until(tok.Expiry)
			if remaining > 0 {
				refreshAt = time.Now().Add(remaining / 2)
			} else {
				refreshAt = time.Now().Add(10 * time.Second)
			}
		}

		return valkey.AuthCredentials{
			Username:     p.username,
			Password:     tok.AccessToken,
			RefreshAfter: refreshAt,
		}, nil
	}
}

// WithDefaultIAM configures the client to authenticate using Application Default Credentials.
func WithDefaultIAM() GCPOption {
	return func(opt *valkey.ClientOption) error {
		provider, err := NewGCPTokenProvider(context.Background(), IAMAuthOptions{})
		if err != nil {
			return err
		}
		opt.AuthCredentialsFn = provider.AuthCredentialsFn()
		return nil
	}
}

// WithIAMOptions configures custom IAM authentication options.
func WithIAMOptions(iamOpt IAMAuthOptions) GCPOption {
	return func(opt *valkey.ClientOption) error {
		provider, err := NewGCPTokenProvider(context.Background(), iamOpt)
		if err != nil {
			return err
		}
		opt.AuthCredentialsFn = provider.AuthCredentialsFn()
		return nil
	}
}
