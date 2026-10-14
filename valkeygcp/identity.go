package valkeygcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2/google"
)

// UsernameStrategy selects the username sent with IAM AUTH when IAMAuthOptions.Username is empty (U4).
type UsernameStrategy int

const (
	UsernameDefault        UsernameStrategy = iota // "default": the only IAM username the IAM docs list
	UsernamePrincipalEmail                         // IAM principal email, for ACL policies keyed by email (Q1)
)

// Metadata server lookups. They are variables because metadata.OnGCEWithContext caches its
// answer for the whole process, which tests need to bypass.
var (
	metadataOnGCE = metadata.OnGCEWithContext
	metadataEmail = metadata.EmailWithContext
)

// resolveUsername: explicit Username > strategy. credsJSON is IAMAuthOptions.CredentialsJSON
// or google.Credentials.JSON from ADC (nil on the metadata server).
func resolveUsername(ctx context.Context, opt IAMAuthOptions, credsJSON []byte) (string, error) {
	if opt.Username != "" {
		return opt.Username, nil
	}
	if opt.UsernameStrategy != UsernamePrincipalEmail {
		return DefaultIAMUsername, nil
	}
	if opt.ImpersonateSA != "" {
		return opt.ImpersonateSA, nil
	}
	var f struct {
		ClientEmail                    string `json:"client_email"`                      // service_account keys
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"` // WIF configs
	}
	if len(credsJSON) > 0 && json.Unmarshal(credsJSON, &f) == nil {
		if f.ClientEmail != "" {
			return f.ClientEmail, nil
		}
		if i := strings.LastIndex(f.ServiceAccountImpersonationURL, "/serviceAccounts/"); i >= 0 {
			email := f.ServiceAccountImpersonationURL[i+len("/serviceAccounts/"):]
			return strings.TrimSuffix(email, ":generateAccessToken"), nil
		}
	}
	if metadataOnGCE(ctx) { // GCE, GKE Workload Identity, Cloud Run
		email, err := metadataEmail(ctx, "default")
		if err != nil {
			return "", fmt.Errorf("valkeygcp: read the principal email from the metadata server (or set IAMAuthOptions.Username): %w", err)
		}
		if email == "" {
			return "", errors.New("valkeygcp: the metadata server returned no principal email; set IAMAuthOptions.Username")
		}
		return email, nil
	}
	return "", errors.New("valkeygcp: cannot resolve the principal email; set IAMAuthOptions.Username")
}

// credTypeFromJSON lets NewGCPTokenProvider call google.CredentialsFromJSONWithType instead of
// the deprecated google.CredentialsFromJSON (Correction V10, as on the branch).
func credTypeFromJSON(b []byte) google.CredentialsType {
	var h struct {
		Type google.CredentialsType `json:"type"`
	}
	if json.Unmarshal(b, &h) != nil || h.Type == "" {
		return google.ServiceAccount // invalid JSON still fails inside CredentialsFromJSONWithType
	}
	return h.Type
}
