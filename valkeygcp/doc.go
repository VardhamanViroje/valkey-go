// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication.
//
// NewClient takes the same valkey.ClientOption as valkey.NewClient, plus Options, and
// returns a ready valkey.Client wired for IAM authentication, Token Auth and TLS.
// WithInstance reads an instance's security settings (auth mode, in-transit encryption and
// server CA, cluster mode, PSC endpoints) and fills in what the ClientOption leaves empty.
// WithIAMOptions, WithDefaultIAM and WithTokenAuth add credentials, and WithTLS adds TLS
// from CA material. ResolveClientOption returns the wired valkey.ClientOption without
// connecting, for valkey.NewClient or other valkey-go modules.
package valkeygcp
