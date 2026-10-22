// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication.
//
// NewClusterClient and NewStandaloneClient return a valkey.Client with Memorystore-friendly
// connection defaults, configured with options such as WithDefaultIAM and WithIAMOptions.
// WithDefaultIAM authenticates with IAM access tokens from Application Default Credentials,
// renewed on open connections before they expire.
package valkeygcp
