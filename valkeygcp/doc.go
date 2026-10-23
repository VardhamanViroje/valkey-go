// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication.
//
// NewClient takes the same valkey.ClientOption as valkey.NewClient, fills in
// Memorystore-friendly connection defaults, and adds the credentials its Options ask for.
// WithDefaultIAM authenticates with IAM access tokens from Application Default Credentials,
// renewed on open connections before they expire. ResolveClientOption returns the wired
// valkey.ClientOption without connecting, for valkey.NewClient or other valkey-go modules.
package valkeygcp
