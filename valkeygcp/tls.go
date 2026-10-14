package valkeygcp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/valkey-io/valkey-go"
)

// buildTLSConfig turns the resolved mode plus CA material into a *tls.Config.
// Precedence: TLS.CAPEM > TLS.CAFile > PEMs discovered from the Memorystore API > TLS.Base.RootCAs.
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
	// ServerName stays empty by default: tls.Dialer (valkey.go:620) then verifies each
	// node's dialed IP against its certificate (Q3).
	return cfg, nil
}

// errNeedsCA reports a TLS mode without CA material. Customer-managed CAs (Certificate
// Authority Service) can't be downloaded from the Memorystore API.
func errNeedsCA(mode TLSMode) error {
	if mode == TLSCustomCA {
		return fmt.Errorf("valkeygcp: TLS mode %v needs CA certificates: set TLS.CAPEM or TLS.CAFile", mode)
	}
	return fmt.Errorf("valkeygcp: TLS mode %v needs CA certificates: set TLS.CAPEM or TLS.CAFile, or Config.Instance to download them", mode)
}

// WithTLS wires TLS with caller-supplied CA material into the low-level constructors.
func WithTLS(opt TLSOptions) GCPOption {
	return func(o *valkey.ClientOption) error {
		mode := opt.Mode
		if mode == TLSAuto {
			mode = TLSCustomCA
		}
		cfg, err := buildTLSConfig(opt, mode, nil)
		if err != nil {
			return err
		}
		o.TLSConfig = cfg
		return nil
	}
}

