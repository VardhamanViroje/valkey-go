# valkeygcp: Google Cloud Memorystore Integration for Valkey-Go

[![Go Reference](https://pkg.go.dev/badge/github.com/valkey-io/valkey-go/valkeygcp.svg)](https://pkg.go.dev/github.com/valkey-io/valkey-go/valkeygcp)

`valkeygcp` is the official Google Cloud sub-module for [`valkey-go`](https://github.com/valkey-io/valkey-go), integrating it with **Google Cloud Memorystore for Valkey**.

---

## 1. Native Google Cloud IAM Authentication

`valkeygcp` provides **Native Google Cloud IAM Authentication** and connection management for Memorystore for Valkey. `valkeygcp.NewClusterClient` and `valkeygcp.NewStandaloneClient` connect with Memorystore-friendly defaults, and `valkeygcp.WithDefaultIAM()` authenticates with IAM OAuth2 access tokens from Application Default Credentials (ADC) instead of a password. Tokens are renewed on open connections before they expire, so connections keep working past token expiry.

### 1.1 Installation

```bash
go get github.com/valkey-io/valkey-go/valkeygcp
```

### 1.2 Quickstart

#### Connect with Default IAM (Cluster Mode)

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

### 1.3 Contexts, Timeouts and Setup Failures

* **The constructor's `ctx` bounds setup only.** `NewClusterClient` and `NewStandaloneClient` pass it to every option. Credential discovery stops when it is cancelled or its deadline passes, and after 15 seconds if it has no deadline; a `ctx` that has ended by then stops the constructor before it connects. Token refreshes never use it, because they run for the life of the client.
* **Token fetches are capped.** Each IAM token fetch waits at most `IAMAuthOptions.FetchTimeout` (default 10s; negative disables the cap). A timed-out fetch is handled like any failed fetch: live connections keep the last valid token, and `IAMAuthOptions.OnCredentialError` reports it.
* **Setup needs working credentials.** valkey-go connects and authenticates while it builds the client, so missing ADC fails the constructor immediately, with the underlying error. Without ADC, pass a token source in `IAMAuthOptions.CustomTokenSource`.
* **A rejected re-AUTH closes the connection.** If Memorystore rejects a proactive re-AUTH (for example with `ERR_IAM_EXHAUSTED`), valkey-go closes that connection and the next command dials again (`pipe.go` `refreshAuth`), although Memorystore would keep the authenticated connection working.
* **Custom options** for the constructors have the signature `func(ctx context.Context, opt *valkey.ClientOption) error`.

### 1.4 Required Roles

| Mechanism | Role on the workload identity                                          |
| :-------- | :--------------------------------------------------------------------- |
| IAM Auth  | `roles/memorystore.dbConnectionUser` (`memorystore.instances.connect`) |

---

## 2. In-Transit Encryption (TLS)

Instances with in-transit encryption turned on accept only TLS connections. `valkeygcp.WithTLS` turns TLS on for `NewClusterClient` and `NewStandaloneClient` and checks every node's certificate against the instance's server CA certificates, with TLS 1.2 or later. You supply the CA certificates, as a PEM file in `TLSOptions.CAFile` or as PEM bytes in `TLSOptions.CAPEM`. TLS needs no extra role on the workload identity.

### 2.1 Get the Server CA Certificates

The instance's server CA mode decides where the certificates come from:

```bash
gcloud memorystore instances describe INSTANCE --location=REGION \
  --format="value(transitEncryptionMode,serverCaMode,serverCaPool)"
```

Save them with the command for that mode. Keep every certificate the command returns:

```bash
# GOOGLE_MANAGED_PER_INSTANCE_CA, or empty on older instances: TLSPerInstanceCA
gcloud memorystore instances get-certificate-authority INSTANCE --location=REGION --format=json \
  | jq -r '.. | strings | select(contains("BEGIN CERTIFICATE"))' > server-ca.pem

# GOOGLE_MANAGED_SHARED_CA: TLSSharedCA
gcloud memorystore instances get-shared-regional-certificate-authority --location=REGION --format=json \
  | jq -r '.. | strings | select(contains("BEGIN CERTIFICATE"))' > server-ca.pem

# CUSTOMER_MANAGED_CAS_CA: TLSCustomCA (SERVER_CA_POOL is the instance's serverCaPool)
gcloud privateca pools get-ca-certs SERVER_CA_POOL --output-file=server-ca.pem
```

The Memorystore commands need read access to the instance, for example `roles/memorystore.viewer`. The CA Service command needs `privateca.caPools.get` on the pool (`roles/privateca.poolReader`).

### 2.2 Connect with TLS

```go
// Cluster mode, IAM authentication, per-instance CA:
client, err := valkeygcp.NewClusterClient(ctx, "10.0.0.15:6379",
	valkeygcp.WithDefaultIAM(),
	valkeygcp.WithTLS(valkeygcp.TLSOptions{Mode: valkeygcp.TLSPerInstanceCA, CAFile: "/etc/memorystore/server-ca.pem"}),
)

// Cluster mode disabled, no authentication, shared regional CA:
client, err := valkeygcp.NewStandaloneClient(ctx, "10.0.0.2:6379", "10.0.0.3:6379",
	valkeygcp.WithTLS(valkeygcp.TLSOptions{Mode: valkeygcp.TLSSharedCA, CAFile: "/etc/memorystore/server-ca.pem"}),
)
```

* **Every certificate in the bundle is trusted.** A file saved while the instance has more than one CA, for example during a server CA rotation, verifies nodes signed by any of them. The file is read once, when the client is created; after replacing it, create a new client. Per-instance CAs are valid for ten years and the next one can be downloaded about five years before the current one expires, so save the file again from time to time.
* **Nodes are checked by IP address.** `ServerName` stays empty, so valkey-go checks each node's certificate against the IP address it dials. Set `TLSOptions.ServerName` only to check against another name.
* **No CA, no connection.** Without CA certificates `WithTLS` fails with `needs CA certificates` instead of connecting unverified, and a certificate from another CA fails the handshake (`x509: certificate signed by unknown authority`).
* **`TLSOptions.Base`** is an optional `*tls.Config` to start from. It is cloned, never changed, and its `MinVersion` is raised to TLS 1.2. Its `RootCAs` are used when `CAPEM` and `CAFile` are empty. Its other settings are kept as they are, so `InsecureSkipVerify` still turns verification off.
* **`TLSOptions.Mode`** names the instance's server CA mode and appears in errors. `TLSAuto`, the zero value, works like `TLSCustomCA`; `TLSDisabled` leaves TLS off; other values are rejected.

### 2.3 Live Check

`cmd/live_tls` connects to a real instance through the constructors, PINGs every node (each one a separate TLS handshake) and runs SET and GET. Run it on a VM in the instance's VPC network:

```bash
go run ./cmd/live_tls -primary=10.0.0.2:6379 -reader=10.0.0.3:6379 -ca-file=server-ca.pem -tls-mode=shared
go run ./cmd/live_tls -discovery=10.0.0.15:6379 -ca-file=server-ca.pem -tls-mode=per-instance -iam
```

The last line is `RESULT {"ok":true,...}` when every node answered over TLS. `-duration=70m` keeps SET/GET traffic going and logs `STATS` every minute. With `-iam`, every login is logged as an `AUTH` line with a short hash of the token, never the token itself, so a long run shows when the token is renewed. `-conn-lifetime=5m` closes and reopens every connection every five minutes, so new logins and TLS handshakes keep happening during the run.
