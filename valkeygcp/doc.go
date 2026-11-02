// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication and in-transit encryption.
//
// NewClusterClient and NewStandaloneClient return a valkey.Client with Memorystore-friendly
// connection defaults, configured with options such as WithDefaultIAM, WithIAMOptions and
// WithTLS. WithDefaultIAM authenticates with IAM access tokens from Application Default
// Credentials, renewed on open connections before they expire. WithTLS encrypts the
// connections and verifies every node against the instance's server CA certificates.
package valkeygcp
