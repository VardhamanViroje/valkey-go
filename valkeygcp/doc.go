// Package valkeygcp connects valkey-go to Google Cloud Memorystore for Valkey with native
// Google Cloud authentication.
//
// NewClient takes the same valkey.ClientOption as valkey.NewClient, plus Options, and
// returns a ready valkey.Client:
//
//	client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{
//		InitAddress: []string{"10.0.0.15:6379"}, // the instance's discovery endpoint
//	},
//		valkeygcp.WithDefaultIAM(),
//		valkeygcp.WithTLS(valkeygcp.TLSOptions{CAFile: "server-ca.pem"}),
//	)
//
// The Options add what valkey-go has no field for:
//   - WithDefaultIAM and WithIAMOptions authenticate with IAM access tokens, which are
//     replaced on live connections before they expire.
//   - WithTokenAuth authenticates with a Token Auth token, for example from Secret Manager.
//   - WithTLS turns on in-transit encryption with the instance's server CA.
//   - WithInstance reads the instance's settings (endpoints, auth mode, TLS mode and server
//     CA, cluster mode) and fills in what the ClientOption leaves empty.
//
// ResolveClientOption returns the same valkey.ClientOption without connecting, for
// valkey.NewClient or other valkey-go modules such as valkeyotel.
package valkeygcp
