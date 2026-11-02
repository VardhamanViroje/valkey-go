// Package cas reads the CA certificates of a Certificate Authority Service CA pool, for
// Memorystore for Valkey instances whose server CA mode is CUSTOMER_MANAGED_CAS_CA. The
// Memorystore API can't return those certificates, so plug FetchPoolCAs into
// valkeygcp.TLSOptions.FetchCustomCA:
//
//	client, err := valkeygcp.NewClient(ctx, valkey.ClientOption{},
//		valkeygcp.WithInstance("projects/P/locations/R/instances/I"),
//		valkeygcp.WithTLS(valkeygcp.TLSOptions{FetchCustomCA: cas.FetchPoolCAs}),
//	)
//
// It is a separate package so that only programs that use it link the CA Service client.
package cas

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/api/option"
	privateca "google.golang.org/api/privateca/v1"
)

// FetchPoolCAs returns every certificate in the CA chains of caPool
// ("projects/P/locations/L/caPools/POOL"). Its CA Service client is built with opts, which
// valkeygcp sets to the identity of its other setup calls (the WithIAMOptions identity,
// otherwise Application Default Credentials) followed by valkeygcp.WithGoogleAPIOptions. The
// identity needs privateca.caPools.get on the pool, for example through
// roles/privateca.poolReader. The chains cover the pool's CAs in the ENABLED, DISABLED and
// STAGED states, so certificates from a CA that is being rotated in still verify.
func FetchPoolCAs(ctx context.Context, caPool string, opts ...option.ClientOption) ([]string, error) {
	return Fetcher()(ctx, caPool, opts...)
}

// Fetcher returns a FetchPoolCAs whose CA Service client also gets opts, for example
// option.WithCredentialsFile. They come after the options of each call, so they win.
func Fetcher(opts ...option.ClientOption) func(ctx context.Context, caPool string, callOpts ...option.ClientOption) ([]string, error) {
	return func(ctx context.Context, caPool string, callOpts ...option.ClientOption) ([]string, error) {
		svc, err := privateca.NewService(ctx, slices.Concat(callOpts, opts)...)
		if err != nil {
			return nil, fmt.Errorf("cas: CA Service client: %w", err)
		}
		resp, err := svc.Projects.Locations.CaPools.FetchCaCerts(caPool, &privateca.FetchCaCertsRequest{}).Context(ctx).Do()
		if err != nil {
			return nil, fmt.Errorf("cas: fetchCaCerts %s: %w", caPool, err)
		}
		var pems []string
		for _, chain := range resp.CaCerts {
			pems = append(pems, chain.Certificates...)
		}
		return pems, nil
	}
}
