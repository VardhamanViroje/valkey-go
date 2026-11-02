package valkeygcp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// buildTLSConfig turns the resolved TLS mode and CA material into a *tls.Config, or nil when
// TLS is off. The CA comes from the first of: TLSOptions.CAPEM, TLSOptions.CAFile, the
// certificates downloaded from the Memorystore API, TLSOptions.Base.RootCAs.
func buildTLSConfig(opt TLSOptions, mode TLSMode, discovered []string) (*tls.Config, error) {
	if mode == TLSDisabled || mode == TLSAuto {
		return nil, nil
	}
	pemBytes := opt.CAPEM
	if len(pemBytes) == 0 && opt.CAFile != "" {
		b, err := os.ReadFile(opt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("valkeygcp: read TLS.CAFile: %w", err)
		}
		pemBytes = b
	}
	if len(pemBytes) == 0 && len(discovered) > 0 {
		pemBytes = []byte(strings.Join(discovered, "\n"))
	}
	var pool *x509.CertPool
	switch {
	case len(pemBytes) > 0:
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("valkeygcp: no valid PEM certificate in the CA bundle")
		}
	case opt.Base != nil && opt.Base.RootCAs != nil:
		pool = opt.Base.RootCAs // caller-built pool, kept as is
	default:
		return nil, errNeedsCA(mode)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12} // Memorystore supports TLS 1.2+
	if opt.Base != nil {
		cfg = opt.Base.Clone()
		if cfg.MinVersion < tls.VersionTLS12 {
			cfg.MinVersion = tls.VersionTLS12
		}
	}
	cfg.RootCAs = pool
	if opt.ServerName != "" {
		cfg.ServerName = opt.ServerName
	}
	// ServerName stays empty by default: Go's tls.Dialer then checks each node's certificate
	// against the IP address it dialed, so one config works for every node of a cluster.
	return cfg, nil
}

// errNeedsCA reports a TLS mode without CA material. Customer-managed CAs (Certificate
// Authority Service) can't be downloaded from the Memorystore API; TLSOptions.FetchCustomCA
// reads them from the CA pool instead.
func errNeedsCA(mode TLSMode) error {
	if mode == TLSCustomCA {
		return fmt.Errorf("valkeygcp: TLS mode %v needs CA certificates: pass WithTLS with TLSOptions.CAPEM or CAFile, or TLSOptions.FetchCustomCA (package valkeygcp/cas) with WithInstance", mode)
	}
	return fmt.Errorf("valkeygcp: TLS mode %v needs CA certificates: pass WithTLS with TLSOptions.CAPEM or CAFile, or use WithInstance to download them", mode)
}

// WithTLS turns on TLS with the CA material in opt (CAPEM, CAFile, Base.RootCAs, or
// FetchCustomCA with WithInstance). With Mode TLSDisabled it states that the instance has
// in-transit encryption disabled, which lets IAM and Token Auth credentials be sent without
// TLS when there is no instance; otherwise NewClient refuses to send them in plaintext. A
// ClientOption.TLSConfig, when set, is used as is instead.
func WithTLS(opt TLSOptions) Option {
	return func(c *config) { c.tls = opt }
}
