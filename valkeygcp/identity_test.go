package valkeygcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2/google"
)

// fakeMetadata points the metadata seams at a test metadata server, or at none when srv is nil.
func fakeMetadata(t *testing.T, srv *httptest.Server) {
	t.Helper()
	origOnGCE, origEmail := metadataOnGCE, metadataEmail
	t.Cleanup(func() { metadataOnGCE, metadataEmail = origOnGCE, origEmail })
	if srv == nil {
		metadataOnGCE = func(context.Context) bool { return false }
		return
	}
	// The real metadata client honours GCE_METADATA_HOST on every request.
	t.Setenv("GCE_METADATA_HOST", srv.Listener.Addr().String())
	metadataOnGCE = func(context.Context) bool { return true }
}

func TestUsername_Strategies(t *testing.T) {
	fakeMetadata(t, nil)
	const (
		saKey = `{"type":"service_account","client_email":"key@p.iam.gserviceaccount.com"}`
		wif   = `{"type":"external_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wif@p.iam.gserviceaccount.com:generateAccessToken"}`
	)
	cases := []struct {
		id   string
		opt  IAMAuthOptions
		json string
		want string
	}{
		{"T-ID-1", IAMAuthOptions{Username: "explicit", UsernameStrategy: UsernamePrincipalEmail, ImpersonateSA: "sa@p.iam.gserviceaccount.com"}, saKey, "explicit"},
		{"T-ID-2", IAMAuthOptions{}, saKey, DefaultIAMUsername},
		{"T-ID-3", IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail, ImpersonateSA: "sa@p.iam.gserviceaccount.com"}, saKey, "sa@p.iam.gserviceaccount.com"},
		{"T-ID-4", IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, saKey, "key@p.iam.gserviceaccount.com"},
		{"T-ID-5", IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, wif, "wif@p.iam.gserviceaccount.com"},
	}
	for _, c := range cases {
		got, err := resolveUsername(context.Background(), c.opt, []byte(c.json))
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.id, got, err, c.want)
		}
	}
}

// T-ID-6
func TestUsername_MetadataServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/email" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("workload@p.iam.gserviceaccount.com"))
	}))
	defer srv.Close()
	fakeMetadata(t, srv)

	got, err := resolveUsername(context.Background(), IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, nil)
	if err != nil || got != "workload@p.iam.gserviceaccount.com" {
		t.Fatalf("got %q, %v", got, err)
	}
	// User credentials JSON carries no email: fall through to the metadata server.
	got, err = resolveUsername(context.Background(), IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, []byte(`{"type":"authorized_user"}`))
	if err != nil || got != "workload@p.iam.gserviceaccount.com" {
		t.Fatalf("authorized_user: got %q, %v", got, err)
	}
}

func TestUsername_MetadataServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	fakeMetadata(t, srv)
	metadataEmail = func(context.Context, string) (string, error) { return "", errors.New("metadata down") }
	if _, err := resolveUsername(context.Background(), IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, nil); err == nil ||
		!strings.Contains(err.Error(), "metadata down") {
		t.Fatalf("got %v", err)
	}
	metadataEmail = func(context.Context, string) (string, error) { return "", nil }
	if _, err := resolveUsername(context.Background(), IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, nil); err == nil {
		t.Fatal("an empty email must not become the username")
	}
}

// T-ID-7
func TestUsername_Unresolvable(t *testing.T) {
	fakeMetadata(t, nil)
	_, err := resolveUsername(context.Background(), IAMAuthOptions{UsernameStrategy: UsernamePrincipalEmail}, []byte(`{ not json`))
	if err == nil || !strings.Contains(err.Error(), "IAMAuthOptions.Username") {
		t.Fatalf("got %v", err)
	}
	// The provider surfaces the same error at construction.
	_, err = NewGCPTokenProvider(context.Background(), IAMAuthOptions{CustomTokenSource: staticIAM().CustomTokenSource, UsernameStrategy: UsernamePrincipalEmail})
	if err == nil {
		t.Fatal("NewGCPTokenProvider accepted an unresolvable principal email")
	}
}

func TestCredTypeFromJSON(t *testing.T) {
	for in, want := range map[string]google.CredentialsType{
		`{"type":"external_account"}`: google.ExternalAccount,
		`{"type":"authorized_user"}`:  google.AuthorizedUser,
		`{}`:                          google.ServiceAccount,
		`{ invalid`:                   google.ServiceAccount,
	} {
		if got := credTypeFromJSON([]byte(in)); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}
