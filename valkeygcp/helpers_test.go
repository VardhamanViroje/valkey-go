package valkeygcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"golang.org/x/oauth2"
)

const testInstance = "projects/my-proj/locations/us-west4/instances/my-valkey"

// tokenSourceFunc adapts a function to oauth2.TokenSource.
type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

// staticIAM is an IAM option set that never touches ADC.
func staticIAM() IAMAuthOptions {
	return IAMAuthOptions{CustomTokenSource: oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "iam-token",
		Expiry:      time.Now().Add(time.Hour),
	})}
}

// fakeReader is an in-memory instanceReader.
type fakeReader struct {
	inst   *memorystorepb.Instance
	getErr error
	caErr  error

	perCA    []string
	sharedCA []string

	gotName                     string
	perCalls, sharedCalls       int
	perName                     string
	sharedProject, sharedRegion string
	closed                      bool
}

func (f *fakeReader) GetInstance(_ context.Context, name string) (*memorystorepb.Instance, error) {
	f.gotName = name
	return f.inst, f.getErr
}

func (f *fakeReader) PerInstanceCA(_ context.Context, name string) ([]string, error) {
	f.perCalls++
	f.perName = name
	return f.perCA, f.caErr
}

func (f *fakeReader) SharedRegionalCA(_ context.Context, project, region string) ([]string, error) {
	f.sharedCalls++
	f.sharedProject, f.sharedRegion = project, region
	return f.sharedCA, f.caErr
}

func (f *fakeReader) Close() error {
	f.closed = true
	return nil
}

func (f *fakeReader) factory() func(context.Context) (instanceReader, error) {
	return func(context.Context) (instanceReader, error) { return f, nil }
}

// autoConn is an endpoints[].connections[] entry created by service connectivity automation.
func autoConn(ip string, port int32, typ memorystorepb.ConnectionType, network string) *memorystorepb.Instance_ConnectionDetail {
	return &memorystorepb.Instance_ConnectionDetail{Connection: &memorystorepb.Instance_ConnectionDetail_PscAutoConnection{
		PscAutoConnection: &memorystorepb.PscAutoConnection{
			IpAddress:      ip,
			Ports:          &memorystorepb.PscAutoConnection_Port{Port: port},
			ConnectionType: typ,
			Network:        network,
		},
	}}
}

// userConn is a user-created PSC connection.
func userConn(ip string, port int32, typ memorystorepb.ConnectionType, network string) *memorystorepb.Instance_ConnectionDetail {
	return &memorystorepb.Instance_ConnectionDetail{Connection: &memorystorepb.Instance_ConnectionDetail_PscConnection{
		PscConnection: &memorystorepb.PscConnection{
			IpAddress:      ip,
			Ports:          &memorystorepb.PscConnection_Port{Port: port},
			ConnectionType: typ,
			Network:        network,
		},
	}}
}

func endpointGroup(conns ...*memorystorepb.Instance_ConnectionDetail) *memorystorepb.Instance_InstanceEndpoint {
	return &memorystorepb.Instance_InstanceEndpoint{Connections: conns}
}

// testCA is a throwaway certificate authority.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t testing.TB, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a server certificate for 127.0.0.1, like a Memorystore node certificate with an IP SAN.
func (ca *testCA) leaf(t testing.TB) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "node"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert
}
