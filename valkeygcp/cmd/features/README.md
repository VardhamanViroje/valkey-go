# Try valkeygcp

These examples are what you would write when trying valkeygcp for the first time. Each one is a single `main.go` that you can read top to bottom and copy into your own project. Run them from the `valkeygcp` directory, in the order below.

## Before you start

1. A Memorystore for Valkey instance with IAM authentication.
2. A machine in the instance's VPC network, such as a Compute Engine VM or a GKE pod.
3. An identity with `roles/memorystore.dbConnectionUser` on the instance. On Google Cloud this is usually the service account of the VM or pod, which valkeygcp finds through Application Default Credentials (ADC).
4. The instance's endpoints: the discovery endpoint for cluster mode, or the primary and reader endpoints with cluster mode disabled.
5. If the instance uses in-transit encryption, its server CA certificate in a PEM file. Pass it to any example with `-ca server-ca.pem`.

## The examples

| Example               | What it shows                                                                        | Run                                                                                  |
| :-------------------- | :----------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- |
| `quickstart`          | Connect to a cluster-mode instance with `WithDefaultIAM`, then SET and GET           | `go run ./cmd/features/quickstart -addr 10.0.0.15:6379`                              |
| `standalone`          | Cluster mode disabled: writes to the primary, reads from the reader                  | `go run ./cmd/features/standalone -primary 10.0.0.2:6379 -reader 10.0.0.3:6379`      |
| `iam_options`         | Every `IAMAuthOptions` field, set with `WithIAMOptions`                               | `go run ./cmd/features/iam_options -addr 10.0.0.15:6379`                             |
| `custom_token_source` | Tokens from your own `oauth2.TokenSource`, here a service account key file           | `go run ./cmd/features/custom_token_source -addr 10.0.0.15:6379 -key-file key.json`  |
| `token_refresh`       | Tokens renewed on a live connection; `-disable-reauth` turns that off                | `go run ./cmd/features/token_refresh -addr 10.0.0.15:6379`                           |
| `refresh_failure`     | A token source that breaks: `OnCredentialError`, the last token kept, `FetchTimeout` | `go run ./cmd/features/refresh_failure -addr 10.0.0.15:6379`                         |
| `pacing`              | `MaxAuthPerSecond` spreading out the AUTHs of many new connections                   | `go run ./cmd/features/pacing -addr 10.0.0.15:6379`                                  |
| `resolve_option`      | `ResolveClientOption`: see the settings, then build the client yourself              | `go run ./cmd/features/resolve_option -addr 10.0.0.15:6379`                          |
| `token_provider`      | `NewGCPTokenProvider` with plain `valkey.NewClient`                                   | `go run ./cmd/features/token_provider -addr 10.0.0.15:6379`                          |
| `valkeylock`          | `NewClient` as the `ClientBuilder` of `valkeylock`                                    | `go run ./cmd/features/valkeylock -addr 10.0.0.15:6379`                              |
| `common_errors`       | The errors common mistakes cause, so you can recognize them                          | `go run ./cmd/features/common_errors -addr 10.0.0.15:6379`                           |

`-addr` takes the discovery endpoint of a cluster-mode instance, or the primary endpoint of an instance with cluster mode disabled.

`token_refresh` and `refresh_failure` take a minute or two. Real tokens last an hour, so their token source reports a short lifetime to make refreshes happen during the run.

## Where each IAMAuthOptions field is shown

| Field                    | Example                                |
| :----------------------- | :------------------------------------- |
| `Username`               | `iam_options`                          |
| `CustomTokenSource`      | `custom_token_source`                  |
| `Scopes`                 | `iam_options`                          |
| `RefreshBuffer`          | `token_refresh`                        |
| `DisableProactiveReauth` | `token_refresh -disable-reauth`        |
| `FetchTimeout`           | `refresh_failure -hang`, `common_errors` |
| `MaxAuthPerSecond`       | `pacing`                               |
| `OnCredentialError`      | `refresh_failure`                      |

## Trying them without Memorystore

Start a local Valkey with a password, and pass the password with `-local-token`. The examples then send it as a fixed token instead of an IAM token, so you can see how the code behaves before you have an instance:

```bash
docker run -d --rm -p 6379:6379 valkey/valkey valkey-server --requirepass TOKEN
go run ./cmd/features/quickstart -addr 127.0.0.1:6379 -local-token TOKEN
```
