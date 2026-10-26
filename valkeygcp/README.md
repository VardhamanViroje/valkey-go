# valkeygcp: Google Cloud Memorystore Integration for Valkey-Go

[![Go Reference](https://pkg.go.dev/badge/github.com/valkey-io/valkey-go/valkeygcp.svg)](https://pkg.go.dev/github.com/valkey-io/valkey-go/valkeygcp)

`valkeygcp` is the official Google Cloud sub-module for [`valkey-go`](https://github.com/valkey-io/valkey-go), integrating it with **Google Cloud Memorystore for Valkey**.

---

## 1. Native Google Cloud IAM Authentication

`valkeygcp` provides **Native Google Cloud IAM Authentication** and connection management for Memorystore for Valkey. Its entry point, `valkeygcp.NewClient`, takes the same `valkey.ClientOption` as `valkey.NewClient`, as `valkeyotel.NewClient` does, and covers every authentication mechanism Memorystore supports: IAM, Token Auth, in-transit encryption (TLS) and ACL-policy usernames.

### 1.1 Key Features

* **The valkey-go Way:** `valkeygcp.NewClient(ctx, valkey.ClientOption{...}, opts...)` takes a regular `valkey.ClientOption`: endpoints in `InitAddress` and `Standalone.ReplicaAddress`, and any other valkey-go setting. Memorystore defaults only fill the fields you leave at zero. Options add what valkey-go has no field for: `WithInstance`, `WithIAMOptions` or `WithDefaultIAM`, `WithTokenAuth` and `WithTLS`.
* **Auto-Discovery:** `WithInstance` reads the instance (auth mode, TLS mode, server CA, cluster mode, PSC endpoints) and fills in the endpoints, TLS and credentials the `ClientOption` leaves empty. It reads the instance as the identity `WithIAMOptions` names, or as ADC. Settings that contradict the instance fail before any connection is made.
* **IAM Authentication, No Password:** Connections authenticate with Google Cloud IAM access tokens instead of a password. The tokens come from Application Default Credentials (ADC), which finds the identity of a GKE pod (Workload Identity) or a VM (metadata server), or from a service account key.
* **Token Auth (`TOKEN_AUTH`):** Tokens from Secret Manager (recommended; global or regional secrets), a static value or a custom source; reloaded periodically so rotated tokens reach live connections.
* **In-Transit Encryption:** Per-instance, shared regional and customer-managed (CAS) server CAs, TLS 1.2+, every CA chain loaded for overlap during CA rotation. Customer-managed CAs are read from their CA Service pool with `TLSOptions.FetchCustomCA` and the `valkeygcp/cas` package.
* **No Accidental Plaintext Credentials:** Without `WithInstance`, IAM and Token Auth credentials need CA material (`WithTLS` or `ClientOption.TLSConfig`) or an explicit `WithTLS(valkeygcp.TLSOptions{Mode: valkeygcp.TLSDisabled})`.
* **ACL Usernames:** IAM username `"default"` (the default) or the IAM principal email for ACL policies keyed by email. An explicit username that Memorystore would reject fails at setup.
* **Token Refresh on Live Connections:** An IAM access token lasts 60 minutes. valkeygcp caches each token and gets a new one 5 minutes before it expires (`IAMAuthOptions.RefreshBuffer`), and every live connection sends the new token with `AUTH`, without reconnecting or interrupting commands in flight. The re-AUTHs are spread over the first half of those 5 minutes, so connections don't all re-AUTH in the same second.
* **Refresh Failure Tolerance:** If the token source is briefly unreachable, live connections keep the last token that worked instead of being closed, and the refresh is retried about every 30 seconds; `OnCredentialError` reports the failure.
* **Bounded Setup and Token Fetches:** `NewClient`'s `ctx` bounds discovery, credential setup, impersonation and the first Token Auth read. Each IAM token fetch and each Token Auth read is capped, so a hung endpoint can't block new connections (see [1.5](#15-contexts-timeouts-and-setup-failures)).
* **IAM Throttling Backoff:** Memorystore answers `ERR_IAM_EXHAUSTED` (IAM quota exhausted) or `ERR_IAM_OTHER` (a transient IAM error) when it can't check a token right now. `NewClient` retries those errors during the connection handshake with exponential backoff, within its `ctx`, and after such an error new connections wait with the same backoff before dialing. The optional `IAMAuthOptions.MaxAuthPerSecond` limits how many AUTHs are sent per second.
* **Observability:** The `OnAuth` option reports each time credentials are handed to valkey-go: the node address, the username, a token fingerprint (never the token), the next refresh, whether the last token that worked was reused after a failed refresh, and whether the connection is without TLS.
* **Service Account Impersonation:** `IAMAuthOptions.ImpersonateSA` gets tokens for another service account, for example one that can reach an instance in another project. Impersonated tokens can last up to 12 hours (`ImpersonateLifetime`).
* **Works With Other valkey-go Modules:** `NewClient` fits the `ClientBuilder` of `valkeylock`, `valkeylimiter` and `valkeyaside`, and `ResolveClientOption` returns the configured `valkey.ClientOption` for `valkey.NewClient` or `valkeyotel.NewClient`.
* **No Cloud Dependencies in valkey-go:** The Google Cloud SDK dependencies live only in this module; the root `valkey-go` module doesn't depend on them.

### 1.2 Installation

```bash
go get github.com/valkey-io/valkey-go/valkeygcp
```

### 1.3 Quickstart

#### Connect with IAM (Cluster Mode)

```go
package main

import (
	"context"
	"log"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeygcp"
)

func main() {
	ctx := context.Background()

	// IAM access tokens from Application Default Credentials (ADC) or GKE Workload Identity:
	client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{
		InitAddress: []string{"10.0.0.15:6379"}, // discovery endpoint
	},
		valkeygcp.WithDefaultIAM(),
		valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"}),
	)
	if err != nil {
		log.Fatalf("Failed to connect to Memorystore: %v", err)
	}
	defer client.Close()

	// Execute Valkey commands normally - tokens are refreshed in the background:
	err = client.Do(ctx, client.B().Set().Key("mykey").Value("myval").Build()).Error()
	if err != nil {
		log.Fatalf("SET failed: %v", err)
	}
}
```

`InitAddress` holds the discovery endpoint of a cluster-mode instance, or the primary endpoint of a cluster-disabled instance. TLS is on when CA material is supplied, through `WithTLS` or your own `ClientOption.TLSConfig`. Without CA material, IAM and Token Auth credentials are refused, because the AUTH command would cross the network in plaintext; for an instance with in-transit encryption disabled, pass `valkeygcp.WithTLS(valkeygcp.TLSOptions{Mode: valkeygcp.TLSDisabled})`.

#### Connect with Auto-Discovery (any auth mode)

```go
client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{},
	valkeygcp.WithInstance("projects/my-proj/locations/us-west4/instances/my-valkey"),
	// Used only if the instance turns out to use TOKEN_AUTH:
	valkeygcp.WithTokenAuth(valkeygcp.TokenAuthOptions{
		SecretVersion: "projects/my-proj/secrets/valkey-default-token/versions/latest",
	}),
)
```

`WithInstance` fills in what the `ClientOption` leaves empty: the endpoint, the reader endpoint of a cluster-disabled instance, the server CA, and the credentials that match the instance's auth mode. An `IAM_AUTH` instance uses ADC unless you pass `WithIAMOptions`. The instance is read once, while `NewClient` runs, as the identity `WithIAMOptions` names (`CustomTokenSource`, `ImpersonateSA` or `CredentialsJSON`), or as ADC without one; that identity needs `memorystore.instances.get` (`roles/memorystore.viewer`). `WithGoogleAPIOptions` sets other credentials, an endpoint or a quota project for that call. Add `WithNetwork` when the instance has endpoints in several VPC networks. `valkeygcp.ResolveClientOption` returns the configured `valkey.ClientOption` without connecting, so you can inspect or adjust it first.

#### Cluster Mode Disabled with a Reader Endpoint and Token Auth

```go
client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{
	InitAddress: []string{"10.0.0.2:6379"},                                         // primary endpoint
	Standalone:  valkey.StandaloneOption{ReplicaAddress: []string{"10.0.0.3:6379"}}, // reader endpoint
},
	valkeygcp.WithTokenAuth(valkeygcp.TokenAuthOptions{
		SecretVersion: "projects/my-proj/secrets/valkey-default-token/versions/latest",
	}),
	valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"}),
)
```

Read-only commands that don't block go to the reader endpoint. Leave out `Standalone.ReplicaAddress` for an instance without replicas. Leave `TokenAuthOptions.Username` empty for the default user (`AUTH <token>`); set it for other token-auth users (`AUTH <user> <token>`).

#### Cross-Project Service Account Impersonation

```go
client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}},
	valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		ImpersonateSA: "memorystore-reader@database-project.iam.gserviceaccount.com",
	}),
	valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"}),
)
```

The identity that impersonates is ADC, or the key or credential configuration in `CredentialsJSON` when you set it. The impersonated account is also used to read the instance with `WithInstance`.

#### Customer-Managed CA (CA Service)

```go
import "github.com/valkey-io/valkey-go/valkeygcp/cas"

client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{},
	valkeygcp.WithInstance("projects/my-proj/locations/us-west4/instances/my-valkey"),
	valkeygcp.WithTLS(valkeygcp.TLSOptions{FetchCustomCA: cas.FetchPoolCAs}),
)
```

The Memorystore API can't return a customer-managed CA, so `cas.FetchPoolCAs` reads the certificates of the instance's CA pool (`server_ca_pool`) from Certificate Authority Service, as the same identity as the instance lookup (and with `WithGoogleAPIOptions`). That identity needs `privateca.caPools.get` on the pool (`roles/privateca.poolReader`). Without it, pass the CA with `TLSOptions.CAFile` or `TLSOptions.CAPEM`.

#### Use with Other valkey-go Modules

```go
tlsOpt := valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "/etc/memorystore/server-ca.pem"})

// valkeylock, valkeylimiter and valkeyaside build their client through ClientBuilder:
locker, err := valkeylock.NewLocker(valkeylock.LockerOption{
	ClientOption: valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}},
	ClientBuilder: func(option valkey.ClientOption) (valkey.Client, error) {
		return valkeygcp.NewClient(ctx, option, valkeygcp.WithDefaultIAM(), tlsOpt)
	},
})

// valkeyotel builds the client itself, so pass it the ClientOption valkeygcp prepared:
option, err := valkeygcp.ResolveClientOption(ctx, valkey.ClientOption{InitAddress: []string{"10.0.0.15:6379"}},
	valkeygcp.WithDefaultIAM(), tlsOpt)
client, err := valkeyotel.NewClient(option)
```

A client built from `ResolveClientOption` keeps the credentials, TLS and defaults, but not `NewClient`'s connect-time handling: the retries of `ERR_IAM_*` handshake errors and the cluster mode check.

### 1.4 Defaults

`NewClient` fills these into the `valkey.ClientOption` fields you leave at zero:

| Field                                                                        | Default                                                                            |
| :--------------------------------------------------------------------------- | :--------------------------------------------------------------------------------- |
| `Dialer.Timeout` / `Dialer.KeepAlive` / `ConnWriteTimeout`                   | 2s / 1s / 3s                                                                       |
| `RetryDelay`                                                                 | Exponential backoff with full jitter, longer for Memorystore IAM backend errors   |
| `ClusterOption.ShardsRefreshInterval`                                        | 10s                                                                                |
| `ClusterOption.PreferInitAddressRefresh`, `ClusterOption.PreferClusterShards` | Always on: the topology is refreshed through the discovery endpoint with `CLUSTER SHARDS` |
| `SendToReplicas`                                                             | Read-only commands that don't block go to the replicas; set only with `Standalone.ReplicaAddress` |

The cluster settings are left out when `Standalone.ReplicaAddress` is set or the instance is cluster-disabled (from `WithInstance`, or `WithTopology(valkeygcp.TopologyClusterDisabled)`). valkey-go ignores them when it ends up with a single-node client.

### 1.5 Contexts, Timeouts and Setup Failures

* **`NewClient`'s `ctx` bounds setup only.** Discovery, credential discovery, impersonation, the principal-email lookup, the first Token Auth read and connecting stop when it is cancelled or its deadline passes, and after 15 seconds if it has no deadline. Memorystore IAM backend errors during the connection handshake are retried with backoff within that time. Token refreshes never use it, because they run for the life of the client.
* **Token fetches are capped.** Each IAM token fetch waits at most `IAMAuthOptions.FetchTimeout` (default 10s; negative disables the cap), and each Token Auth read at most 5s. A timed-out fetch is handled like any failed fetch: live connections keep the last valid token, and `OnCredentialError` (the `IAMAuthOptions` or `TokenAuthOptions` field, or the `OnCredentialError` option) reports it. A custom `TokenAuthOptions.Source` must return when its `ctx` ends.
* **Setup needs working credentials.** valkey-go connects and authenticates while it builds the client, so missing ADC, a denied impersonation or an unreadable secret fails `NewClient` immediately, with the underlying error. Without ADC, name an identity in `WithIAMOptions` (`CustomTokenSource` or `CredentialsJSON`), which `WithInstance` also uses, or leave out `WithInstance` and set `InitAddress` yourself. Token Auth secrets are read with ADC; use `TokenAuthOptions.Source` or `Token` without it.
* **Cluster mode is checked.** valkey-go falls back to a single-node client when `CLUSTER SHARDS` fails, for example because an ACL rule doesn't allow it. When the instance (`WithInstance`) or `WithTopology(valkeygcp.TopologyCluster)` says cluster mode, `NewClient` fails instead, naming the missing permission.
* **One Secret Manager client per location.** All Token Auth providers share one Secret Manager client per location (global, or each region of a regional secret), created on first use, so creating many clients or retrying setup doesn't pile up gRPC connections. Regional secrets use their regional endpoint, `secretmanager.LOCATION.rep.googleapis.com`, which isn't reachable through Private Google Access.
* **A rejected re-AUTH closes the connection.** If Memorystore rejects the re-AUTH of a live connection (for example with `ERR_IAM_EXHAUSTED`), valkey-go closes that connection and the next command dials a new one, although Memorystore would have kept the authenticated connection working.

### 1.6 IAM Username and ACL Policies

The IAM username is `"default"` unless you set one. When an ACL policy keys its rules by IAM principal email, set `IAMAuthOptions.UsernameStrategy: valkeygcp.UsernamePrincipalEmail`. The email is resolved from, in order: `ImpersonateSA`, the `client_email` of a service account key, the impersonation URL of a Workload Identity Federation config, then the metadata server (GCE, GKE Workload Identity, Cloud Run). An explicit `IAMAuthOptions.Username` always wins; Memorystore accepts only `"default"` or the principal's email, so another value fails at setup when the principal is known.

ACL rules must allow the commands valkey-go sends on every new connection: `client|tracking` (or set `ClientOption.DisableCache`) and, for cluster-mode instances, `cluster|shards`. A smallest working rule is `on ~* -@all +ping +client|tracking +cluster|shards` plus the data commands the application uses. Without `client|tracking`, setup fails with an error naming the rule; without `cluster|shards`, `NewClient` fails instead of returning a single-node client for a cluster (see the cluster mode check in [1.5](#15-contexts-timeouts-and-setup-failures)).

### 1.7 Required Roles

| Mechanism              | Role                                                                          |
| :--------------------- | :---------------------------------------------------------------------------- |
| IAM Auth               | `roles/memorystore.dbConnectionUser` (`memorystore.instances.connect`)        |
| Token Auth             | `roles/secretmanager.secretAccessor` on the token secret                      |
| Auto-discovery and CAs | `roles/memorystore.viewer` (`memorystore.instances.get`)                      |
| Impersonation          | `roles/iam.serviceAccountTokenCreator` on the target service account          |
| Customer-managed CA    | `roles/privateca.poolReader` (`privateca.caPools.get`) on the CA pool          |

Grant them to the identity `WithIAMOptions` names (`CustomTokenSource`, `ImpersonateSA` or `CredentialsJSON`), or to the ADC identity without one: valkeygcp uses that one identity for IAM Auth, the instance lookup and the CA fetch. `WithGoogleAPIOptions` can choose other credentials for the lookup and the CA fetch. With `ImpersonateSA`, the other roles go to the impersonated account, and the identity that impersonates it (ADC, or `CredentialsJSON`) needs `roles/iam.serviceAccountTokenCreator` on it. The Token Auth secret is read with ADC.

### 1.8 Testing

Run unit tests with Go's race detector:

```bash
go test -v -race .
```

The unit tests need no cloud access. `TestRefreshTolerance_LiveConnection` also runs against a local Valkey on `127.0.0.1:6379` (the repository's `docker compose` setup) and is skipped when none is running.

Live checks against real instances live under `cmd/`: `cmd/live_matrix` runs the auth-mode matrix through `valkeygcp.NewClient` (see its package comment for the environment variables), and `cmd/livetest` logs every AUTH with a token fingerprint for soak, rotation and reconnect-storm tests. `cmd/iamprobe` shows the IAM-error backoff against a local fake server, with no cloud access.
