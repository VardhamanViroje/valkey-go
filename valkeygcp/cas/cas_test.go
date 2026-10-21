package cas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/api/option"
)

func testServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/p/locations/l/caPools/pool:fetchCaCerts" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fetcherFor(srv *httptest.Server) func(context.Context, string) ([]string, error) {
	return Fetcher(option.WithEndpoint(srv.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(srv.Client()))
}

// Every certificate of every chain is returned, in order.
func TestFetcher(t *testing.T) {
	srv := testServer(t, http.StatusOK, `{"caCerts":[{"certificates":["A","B"]},{"certificates":["C"]}]}`)
	got, err := fetcherFor(srv)(context.Background(), "projects/p/locations/l/caPools/pool")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("got %q, want A, B, C", got)
	}
}

func TestFetcher_Error(t *testing.T) {
	srv := testServer(t, http.StatusForbidden, `{"error":{"code":403,"message":"Permission 'privateca.caPools.get' denied"}}`)
	_, err := fetcherFor(srv)(context.Background(), "projects/p/locations/l/caPools/pool")
	if err == nil || !strings.Contains(err.Error(), "fetchCaCerts projects/p/locations/l/caPools/pool") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v, want the 403 naming the pool", err)
	}
}

