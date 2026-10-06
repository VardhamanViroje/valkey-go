# valkeygcp: Google Cloud Memorystore Integration for Valkey-Go

[![Go Reference](https://pkg.go.dev/badge/github.com/valkey-io/valkey-go/valkeygcp.svg)](https://pkg.go.dev/github.com/valkey-io/valkey-go/valkeygcp)

`valkeygcp` is the official Google Cloud sub-module for [`valkey-go`](https://github.com/valkey-io/valkey-go), providing **Native Google Cloud IAM Authentication** and connection management for **Google Cloud Memorystore for Valkey**.

---

## Key Features

* **Zero-Password IAM Authentication:** Authenticate using Google Cloud IAM OAuth2 access tokens via Application Default Credentials (ADC), GKE Workload Identity, VM Metadata Server, or Service Account keys.
* **Proactive In-Flight Token Rotation:** Automatically rotates tokens 5 minutes before the 60-minute expiration mark over existing TCP connections using Valkey's RESP3 `AUTH` command without dropping connections or interrupting in-flight queries.
* **Defect C1 Resolution:** Wraps token retrieval with `oauth2.ReuseTokenSourceWithExpiry` with a 5-minute buffer, preventing the recursive token halving loop bug.
* **Enterprise Service Account Impersonation (Gap G6):** Cross-project access via `google.golang.org/api/impersonate`.
* **Zero Core Bloat:** All Google Cloud SDK dependencies remain completely isolated inside this sub-module; root `valkey-go` remains 100% lightweight and cloud-agnostic.

---

## Quickstart

### 1. Installation

```bash
go get github.com/valkey-io/valkey-go/valkeygcp
```

### 2. Connect with Default IAM (Cluster Mode)

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

### 3. Connect with Cross-Project Service Account Impersonation

```go
client, err := valkeygcp.NewClusterClient(ctx, "10.0.0.15:6379",
	valkeygcp.WithIAMOptions(valkeygcp.IAMAuthOptions{
		ImpersonateSA: "memorystore-reader@database-project.iam.gserviceaccount.com",
	}),
)
```

---

## Testing

Run unit tests with Go's race detector:

```bash
go test -v -race .
```
