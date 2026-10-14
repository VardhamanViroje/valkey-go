# valkeygcp: Google Cloud Memorystore Integration for Valkey-Go

[![Go Reference](https://pkg.go.dev/badge/github.com/valkey-io/valkey-go/valkeygcp.svg)](https://pkg.go.dev/github.com/valkey-io/valkey-go/valkeygcp)

`valkeygcp` is the official Google Cloud sub-module for [`valkey-go`](https://github.com/valkey-io/valkey-go), integrating it with **Google Cloud Memorystore for Valkey**.

---

## 1. Native Google Cloud IAM Authentication

`valkeygcp` provides **Native Google Cloud IAM Authentication** and connection management for Memorystore for Valkey. One entry point, `valkeygcp.NewClient`, covers every authentication mechanism Memorystore supports: IAM, Token Auth, in-transit encryption (TLS) and ACL-policy usernames.

### 1.1 Key Features

* **One Call for Every Mechanism:** `valkeygcp.NewClient(ctx, valkeygcp.Config{Instance: ...})` reads the instance (auth mode, TLS mode, server CA, cluster mode, PSC endpoints) and wires the matching credentials, TLS and topology. Explicit settings that contradict the instance fail before any connection is made.
* **Zero-Password IAM Authentication:** Authenticate using Google Cloud IAM OAuth2 access tokens via Application Default Credentials (ADC), GKE Workload Identity, VM Metadata Server, or Service Account keys.
* **Token Auth (`TOKEN_AUTH`):** Tokens from Secret Manager (recommended), a static value or a custom source; reloaded periodically so rotated tokens reach live connections.
* **In-Transit Encryption:** Per-instance, shared regional and customer-managed (CAS) server CAs, TLS 1.2+, every CA chain loaded for overlap during CA rotation.
* **ACL Usernames:** IAM username `"default"` (the default) or the IAM principal email for ACL policies keyed by email.
* **Proactive In-Flight Token Rotation:** Automatically rotates tokens 5 minutes before the 60-minute expiration mark over existing TCP connections using Valkey's RESP3 `AUTH` command without dropping connections or interrupting in-flight queries. Refreshes are spread over the first half of that window so connections don't re-AUTH in the same second.
* **Refresh Failure Tolerance:** If the token source is briefly unreachable, live connections keep the last valid token instead of being closed; `OnCredentialError` reports the failure.
* **Bounded Setup and Token Fetches:** The constructor's `ctx` bounds credential discovery, impersonation and the first Token Auth read. Each IAM token fetch and each Token Auth read is capped, so a hung endpoint can't block new connections (see [1.4](#14-contexts-timeouts-and-setup-failures)).
* **IAM Throttling Backoff:** `ERR_IAM_EXHAUSTED` / `ERR_IAM_OTHER` are retried with a longer exponential backoff; optional `MaxAuthPerSecond` pacing.
* **Defect C1 Resolution:** Wraps token retrieval with `oauth2.ReuseTokenSourceWithExpiry` with a 5-minute buffer, preventing the recursive token halving loop bug.
* **Enterprise Service Account Impersonation (Gap G6):** Cross-project access via `google.golang.org/api/impersonate`, with optional token lifetimes up to 12 hours.
* **Zero Core Bloat:** All Google Cloud SDK dependencies remain completely isolated inside this sub-module; root `valkey-go` remains 100% lightweight and cloud-agnostic.

### 1.2 Installation

```bash
go get github.com/valkey-io/valkey-go/valkeygcp
```

### 1.3 Quickstart

#### Connect with Auto-Discovery (any auth mode)

```go
client, err := valkeygcp.NewClient(ctx, valkeygcp.Config{
	Instance: "projects/my-proj/locations/us-west4/instances/my-valkey",
	// Used only if the instance turns out to use TOKEN_AUTH:
	Auth: valkeygcp.AuthOptions{Token: valkeygcp.TokenAuthOptions{
		SecretVersion: "projects/my-proj/secrets/valkey-default-token/versions/latest",
	}},
})
if err != nil {
	log.Fatalf("Failed to connect to Memorystore: %v", err)
}
defer client.Close()
```

Auto-discovery needs `memorystore.instances.get` (`roles/memorystore.viewer`) at startup. The Memorystore API is only used while `NewClient` runs. `valkeygcp.ResolveClientOption` returns the wired `valkey.ClientOption` without connecting, so you can inspect or adjust it first.

#### Connect with Explicit Settings (no control-plane call)

```go
client, err := valkeygcp.NewClient(ctx, valkeygcp.Config{
	DiscoveryEndpoint: "10.0.0.15:6379", // cluster mode; use PrimaryEndpoint/ReaderEndpoint for cluster-disabled
	Auth:              valkeygcp.AuthOptions{Mode: valkeygcp.AuthIAM},
	TLS:               valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"},
})
```

Without `Instance`, `Auth.Mode` defaults from the options that are set: a token source selects Token Auth, an IAM identity option (such as `CustomTokenSource`, `CredentialsJSON`, `ImpersonateSA` or `Username`) selects IAM, and nothing selects no auth. Plain ADC needs `Mode: valkeygcp.AuthIAM`. TLS is on when CA material is supplied.

#### Connect with Default IAM (Cluster Mode, low-level constructor)

```go
package main

import (
	"context"
	"log"

	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx := context.Background()

	// 1-line connection using Application Default Credentials (ADC) or GKE Workload Identity:
	client, err := valkeygcp.NewClusterClient(ctx, "10.0.0.15:6379", valkeygcp.WithDefaultIAM())
	if err != nil {
		log.Fatalf("Failed to connect to Memorystore: %v", err)
	}
	defer client.Close()

	// Execute Valkey commands normally - token refreshes automatically in the background forever:
	err = client.Do(ctx, client.B().Set().Key("mykey").Value("myval").Build()).Error()
	if err != nil {
		log.Fatalf("SET failed: %v", err)
	}
}
```

#### Connect with Cross-Project Service Account Impersonation

```go
client, err := valkeygcp.NewClusterClient(ctx, "10.0.0.15:6379",
	valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		ImpersonateSA: "memorystore-reader@database-project.iam.gserviceaccount.com",
	}),
)
```

#### Token Auth and TLS with the Low-Level Constructors

```go
client, err := valkeygcp.NewStandaloneClient(ctx, "10.0.0.2:6379", "10.0.0.3:6379",
	valkeygcp.WithTokenAuth(valkeygcp.TokenAuthOptions{
		SecretVersion: "projects/my-proj/secrets/valkey-default-token/versions/latest",
	}),
	valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"}),
)
```

Leave `TokenAuthOptions.Username` empty for the default user (`AUTH <token>`); set it for other token-auth users (`AUTH <user> <token>`).

### 1.4 Contexts, Timeouts and Setup Failures

* **The constructor's `ctx` bounds setup only.** `NewClient`, `NewClusterClient` and `NewStandaloneClient` pass it to discovery and to every option. Credential discovery, impersonation, the principal-email lookup and the first Token Auth read stop when it is cancelled or its deadline passes, and after 15 seconds if it has no deadline. Token refreshes never use it, because they run for the life of the client.
* **Token fetches are capped.** Each IAM token fetch waits at most `IAMAuthOptions.FetchTimeout` (default 10s; negative disables the cap), and each Token Auth read at most 5s. A timed-out fetch is handled like any failed fetch: live connections keep the last valid token, and `OnCredentialError` (on `IAMAuthOptions`, `TokenAuthOptions` or `AuthOptions`) reports it. A custom `TokenAuthOptions.Source` must return when its `ctx` ends.
* **Setup needs working credentials.** valkey-go connects and authenticates while it builds the client, so missing ADC, a denied impersonation or an unreadable secret fails the constructor immediately, with the underlying error. Without ADC, use the explicit path (`DiscoveryEndpoint` or `PrimaryEndpoint`, no control-plane call) with a static or custom Token Auth source, `CustomTokenSource`, `CredentialsJSON`, or no auth.
* **One Secret Manager client per process.** All Token Auth providers share one Secret Manager client, created on first use, so creating many clients or retrying setup doesn't pile up gRPC connections.
* **Custom options** for the low-level constructors have the signature `func(ctx context.Context, opt *valkey.ClientOption) error`.

### 1.5 IAM Username and ACL Policies

The IAM username is `"default"` unless you set one. When an ACL policy keys its rules by IAM principal email, set `IAMAuthOptions.UsernameStrategy: valkeygcp.UsernamePrincipalEmail`. The email is resolved from, in order: `ImpersonateSA`, the `client_email` of a service account key, the impersonation URL of a Workload Identity Federation config, then the metadata server (GCE, GKE Workload Identity, Cloud Run). An explicit `IAMAuthOptions.Username` always wins.

### 1.6 Required Roles

| Mechanism              | Role on the workload identity                                                 |
| :--------------------- | :---------------------------------------------------------------------------- |
| IAM Auth               | `roles/memorystore.dbConnectionUser` (`memorystore.instances.connect`)        |
| Token Auth             | `roles/secretmanager.secretAccessor` on the token secret                      |
| Auto-discovery and CAs | `roles/memorystore.viewer` (`memorystore.instances.get`)                      |
| Impersonation          | `roles/iam.serviceAccountTokenCreator` on the target service account          |

### 1.7 Testing

Run unit tests with Go's race detector:

```bash
go test -v -race .
```

The unit tests need no cloud access. `TestRefreshTolerance_LiveConnection` also runs against a local Valkey on `127.0.0.1:6379` (the repository's `docker compose` setup) and is skipped when none is running.

Live checks against real instances live under `cmd/`; `cmd/live_matrix` runs the auth-mode matrix through `valkeygcp.NewClient` (see its package comment for the environment variables).
