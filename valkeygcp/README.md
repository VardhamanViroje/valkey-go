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
