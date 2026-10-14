// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication.
//
// NewClient reads an instance's security settings (auth mode, in-transit encryption and
// server CA, cluster mode, PSC endpoints) and returns a ready valkey.Client wired for IAM
// authentication, Token Auth and TLS. NewClusterClient and NewStandaloneClient are the
// lower-level constructors, configured with options such as WithDefaultIAM,
// WithIAMOptions, WithTokenAuth and WithTLS.
package valkeygcp

