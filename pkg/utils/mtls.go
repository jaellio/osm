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

	"github.com/openservicemesh/osm/pkg/announcements"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/k8s/events"
	"github.com/openservicemesh/osm/pkg/messaging"
)

// TODO(jaellio): add a stop channel?
type certReloader struct {
	msgBroker *messaging.Broker
	//	certMu      sync.RWMutex
	//	cert        *tls.Certificate
	serverName string
	cn         certificate.CommonName
	configMu   sync.RWMutex
	mutConfig  *tls.Config
}

func newCertReloader(msgBroker *messaging.Broker, insecure bool, serverName string, cn certificate.CommonName, certPem []byte, keyPem []byte, ca []byte) (*certReloader, error) {
	// GetDefaultTLSConfig
	config, err := getDefaultTLSConfig(insecure, serverName, certPem, keyPem, ca)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("Created certificate reloader for the %s server", serverName)
	return &certReloader{
		//cert:        &tlsCert,
		serverName: serverName,
		msgBroker:  msgBroker,
		cn:         cn,
		mutConfig:  config,
	}, nil
}

func (cr *certReloader) start() {
	// https://stackoverflow.com/questions/37473201/is-there-a-way-to-update-the-tls-certificates-in-a-net-http-server-without-any-d

	// Register for certificate rotation updates
	certPubSub := cr.msgBroker.GetCertPubSub()
	certRotateChan := certPubSub.Sub(announcements.CertificateRotated.String())
	defer cr.msgBroker.Unsub(certPubSub, certRotateChan)

	for {
		select {
		case certRotateMsg := <-certRotateChan:
			cert := certRotateMsg.(events.PubSubMessage).NewObj.(*certificate.Certificate)
			// check if the rotated cert is the ads server certificate
			if cert.GetCommonName() != cr.cn {
				continue
			}

			newCert, err := tls.X509KeyPair(cert.GetCertificateChain(), cert.GetPrivateKey())
			if err != nil {
				// TODO(jaellio): Should this error or just log an error?
				log.Error().Msgf("[grpc][mTLS][%s] Failed loading rotated Certificate (%s)", cr.serverName, cert.GetCommonName())
				continue
			}
			certPool := x509.NewCertPool()

			// Load the set of Root CAs
			if ok := certPool.AppendCertsFromPEM(cert.GetTrustedCAs()); !ok {
				log.Error().Msgf("[grpc][mTLS][%s] Failed to append client certs during rotation of Certificate (%s)", cr.serverName, cert.GetCommonName())
				continue
			}

			// TODO(jaellio): should I instead make only the certificates and clientCAs mutable and save those in the cert reloader?
			cr.configMu.RLock()
			cr.mutConfig.ClientCAs = certPool
			cr.mutConfig.Certificates = []tls.Certificate{newCert}
			cr.configMu.RUnlock()

			log.Debug().Msgf("[grpc][mTLS][%s] Successfully updated tls config with rotated Certificate (%s)", cr.serverName, cert.GetCommonName())
		}
		// TODO(jaellio): stop/quit chan
	}
}

func (cr *certReloader) GetConfigForClient(h *tls.ClientHelloInfo) (*tls.Config, error) {
	cr.configMu.RLock()
	defer cr.configMu.RUnlock()
	return cr.mutConfig, nil
}

func setupMutualTLS(insecure bool, serverName string, cr *certReloader) (grpc.ServerOption, error) {
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

func getDefaultTLSConfig(insecure bool, serverName string, certPem []byte, keyPem []byte, ca []byte) (*tls.Config, error) {
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
