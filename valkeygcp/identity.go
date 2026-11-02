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

// UsernameStrategy selects the username sent with IAM AUTH when IAMAuthOptions.Username is
// empty.
type UsernameStrategy int

// UsernameStrategy values.
const (
	UsernameDefault        UsernameStrategy = iota // "default": the only IAM username the IAM docs list
	UsernamePrincipalEmail                         // the IAM principal's email, for ACL policies keyed by email
)

// Metadata server lookups. They are variables because metadata.OnGCEWithContext caches its
// answer for the whole process, which tests need to bypass.
var (
	metadataOnGCE = metadata.OnGCEWithContext
	metadataEmail = metadata.EmailWithContext
)

// resolveUsername returns the AUTH username: Username when set, otherwise the one
// UsernameStrategy picks. For UsernamePrincipalEmail the email comes from ImpersonateSA,
// then credsJSON, then the metadata server. credsJSON is IAMAuthOptions.CredentialsJSON or
// the JSON of the Application Default Credentials (nil on the metadata server).
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
		ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"` // Workload Identity Federation configs
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
		if !strings.Contains(email, "@") {
			// GKE returns SERVICEACCOUNT_NAME.svc.id.goog for Kubernetes ServiceAccounts linked to
			// IAM service accounts unless iam.gke.io/return-principal-id-as-email is set.
			return "", fmt.Errorf("valkeygcp: the metadata server returned %q, which isn't an email; on GKE add the annotation iam.gke.io/return-principal-id-as-email: \"true\" to the Kubernetes ServiceAccount, or set IAMAuthOptions.Username", email)
		}
		return email, nil
	}
	return "", errors.New("valkeygcp: cannot resolve the principal email; set IAMAuthOptions.Username")
}

// checkIAMUsername rejects an explicit IAM username that Memorystore would refuse with
// ERR_IAM_OTHER: "If you specify a username, then you must use either the default
// username or the IAM principal email address". It stays silent when the principal can't
// be determined (a custom token source without credentials JSON, or user credentials off
// Google Cloud), because the username may then be right.
func checkIAMUsername(ctx context.Context, opt IAMAuthOptions, credsJSON []byte) error {
	if opt.Username == "" || opt.Username == DefaultIAMUsername {
		return nil
	}
	if opt.CustomTokenSource != nil && len(credsJSON) == 0 {
		return nil
	}
	email, err := resolveUsername(ctx, IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail, ImpersonateSA: opt.ImpersonateSA}, credsJSON)
	if err != nil || !strings.Contains(email, "@") || strings.EqualFold(email, opt.Username) {
		return nil // principal unknown, or not an email (resolveUsername rejects those)
	}
	return fmt.Errorf("valkeygcp: IAM username %q isn't valid for %s: use %q (or no username) or the principal's email", opt.Username, email, DefaultIAMUsername)
}

// credTypeFromJSON reads the credential type (the "type" field) from credentials JSON, for
// google.CredentialsFromJSONWithType, which replaces the deprecated google.CredentialsFromJSON.
func credTypeFromJSON(b []byte) google.CredentialsType {
	var h struct {
		Type google.CredentialsType `json:"type"`
	}
	if json.Unmarshal(b, &h) != nil || h.Type == "" {
		return google.ServiceAccount // invalid JSON still fails inside CredentialsFromJSONWithType
	}
	return h.Type
}
