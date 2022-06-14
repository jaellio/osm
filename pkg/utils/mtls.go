package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/openservicemesh/osm/pkg/certificate"
)

type CertReloader struct {
	certManager *certificate.Manager
	//	certMu      sync.RWMutex
	//	cert        *tls.Certificate
	cn        certificate.CommonName
	configMu  sync.RWMutex
	mutConfig *tls.Config
}

func (cr *CertReloader) getCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.certMu.RLock()
	defer cr.certMu.RUnlock()
	return cr.cert, nil
}

func NewCertReloader(certManager *certificate.Manager, cert *certificate.Certificate) (*CertReloader, error) {
	tlsCert, err := tls.X509KeyPair(cert.GetCertificateChain(), cert.GetPrivateKey())
	if err != nil {
		return nil, err
	}

	// GetDefaultTLSConfig
	config := getDefaultTLSConfig(cert)

	return &CertReloader{
		certManager: certManager,
		//cert:        &tlsCert,
		cn:        cert.GetCommonName(),
		mutConfig: config,
	}, nil
}

func (cr *CertReloader) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// https://stackoverflow.com/questions/37473201/is-there-a-way-to-update-the-tls-certificates-in-a-net-http-server-without-any-d
	if !cr.certManager.ShouldRotateCertificate(cr.cn) { //|| cr..ShouldRotate() {
		cr.certMu.RLock()
		defer cr.certMu.RUnlock()
		return cr.cert, nil
	}
	cert, rotated, err := cr.certManager.IssueCertificate(cr.cn, constants.XDSCertificateValidityPeriod, certificate.ADS)
	if err != nil {
		return nil, err
	}
	if !rotated {
		cr.certMu.RLock()
		defer cr.certMu.RUnlock()
		return cr.cert, nil
	}
	newCert, err := tls.X509KeyPair(cert.GetCertificateChain(), cert.GetPrivateKey())
	if err != nil {
		// TODO(jaellio): Should we be logging certificates?
		return nil, err
	}
	cr.certMu.RLock()
	defer cr.certMu.RUnlock()
	cr.cert = &newCert
	return cr.cert, nil
}

func (cr *CertReloader) GetConfigForClient(h *tls.ClientHelloInfo) (*tls.Config, error) {
	cr.configMu.RLock()
	defer cr.configMu.RUnlock()
	return cr.mutConfig, nil
}

func setupMutualTLS(insecure bool, serverName string, cr CertReloader) (grpc.ServerOption, error) {
	certPool := x509.NewCertPool()

	// Load the set of Root CAs
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.Errorf("[grpc][mTLS][%s] Failed to append client certs", serverName)
	}

	// #nosec G402
	tlsConfig := tls.Config{
		InsecureSkipVerify: insecure,
		GetConfigForClient: cr.GetConfigForClient,
		ServerName:         serverName,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		//GetCertificate:     cr.GetCertificate,
		//ClientCAs:          certPool,
		MinVersion: tls.VersionTLS13,
	}
	return grpc.Creds(credentials.NewTLS(&tlsConfig)), nil
}

func getDefaultTLSConfig(cert *certificate.Certificate) (*tls.Config, error) {
	certif, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, errors.Errorf("[grpc][mTLS][%s] Failed loading Certificate (%+v) and Key (%+v) PEM files", serverName, certPem, keyPem)
	}

	certPool := x509.NewCertPool()

	// Load the set of Root CAs
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.Errorf("[grpc][mTLS][%s] Failed to append client certs", serverName)
	}

	// #nosec G402
	tlsConfig := tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates:       []tls.Certificate{certif},
		ClientCAs:          certPool,
		MinVersion:         tls.VersionTLS13,
	}
	return &tlsConfig, nil
}

func setupMutualTLS(insecure bool, serverName string, certPem []byte, keyPem []byte, ca []byte) (grpc.ServerOption, error) {
	certif, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, errors.Errorf("[grpc][mTLS][%s] Failed loading Certificate (%+v) and Key (%+v) PEM files", serverName, certPem, keyPem)
	}

	certPool := x509.NewCertPool()

	// Load the set of Root CAs
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.Errorf("[grpc][mTLS][%s] Failed to append client certs", serverName)
	}

	// #nosec G402
	tlsConfig := tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates:       []tls.Certificate{certif},
		ClientCAs:          certPool,
		MinVersion:         tls.VersionTLS13,
	}
	return grpc.Creds(credentials.NewTLS(&tlsConfig)), nil
}

// ValidateClient ensures that the connected client is authorized to connect to the gRPC server.
func ValidateClient(ctx context.Context, allowedCommonNames map[string]interface{}) (certificate.CommonName, certificate.SerialNumber, error) {
	mtlsPeer, ok := peer.FromContext(ctx)
	if !ok {
		log.Error().Msg("[grpc][mTLS] No peer found")
		return "", "", status.Error(codes.Unauthenticated, "no peer found")
	}

	tlsAuth, ok := mtlsPeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		log.Error().Msg("[grpc][mTLS] Unexpected peer transport credentials")
		return "", "", status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}

	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		log.Error().Msgf("[grpc][mTLS] Could not verify peer certificate")
		return "", "", status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}

	// Check whether the subject common name is one that is allowed to connect.
	cn := tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
	if _, ok := allowedCommonNames[cn]; len(allowedCommonNames) > 0 && !ok {
		log.Error().Msgf("[grpc][mTLS] Subject common name %+v not allowed", cn)
		return "", "", status.Error(codes.Unauthenticated, "disallowed subject common name")
	}

	certificateSerialNumber := tlsAuth.State.VerifiedChains[0][0].SerialNumber.String()
	return certificate.CommonName(cn), certificate.SerialNumber(certificateSerialNumber), nil
}
