package certificate

import (
	"math/rand"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/openservicemesh/osm/pkg/announcements"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/k8s/events"
	"github.com/openservicemesh/osm/pkg/messaging"
)

// NewManager creates a new CertManager with the passed CA and CA Private Key
func NewManager(mrcClient MRCClient, getServiceCertValidityPeriod func() time.Duration, getIngressCertValidityDuration func() time.Duration, msgBroker *messaging.Broker) (*Manager, error) {
	// TODO(#4502): transition this call to a watch function that knows how to handle multiple MRC and can react to changes.
	mrcs, err := mrcClient.List()
	if err != nil {
		return nil, err
	}

	client, ca, clientID, err := mrcClient.GetCertIssuerForMRC(mrcs[0])
	if err != nil {
		return nil, err
	}

	c := &issuer{Issuer: client, ID: clientID, CertificateAuthority: ca}

	m := &Manager{
		// The signingIssuer is responsible for signing all newly issued certificates
		// The validatingIssuer is the issuer that issued existing certificates.
		// its underlying cert is still in the validating trust store
		signingIssuer:               c,
		validatingIssuer:            c,
		serviceCertValidityDuration: getServiceCertValidityPeriod,
		ingressCertValidityDuration: getIngressCertValidityDuration,
		msgBroker:                   msgBroker,
	}
	return m, nil
}

// Start takes an interval to check if the certificate
// needs to be rotated
func (m *Manager) Start(checkInterval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(checkInterval)
	go func() {
		m.checkAndRotate()
		for {
			select {
			case <-stop:
				ticker.Stop()
				return
			case <-ticker.C:
				m.checkAndRotate()
			}
		}
	}()
}

// GetTrustDomain returns the trust domain from the configured signingkey issuer.
// Note that the CRD uses a default, so this value will always be set.
func (m *Manager) GetTrustDomain() string {
	// TODO(4754): implement
	return ""
}

// ShouldRotate determines whether a certificate should be rotated.
func (m *Manager) shouldRotate(c *Certificate) bool {
	// The certificate is going to expire at a timestamp T
	// We want to renew earlier. How much earlier is defined in renewBeforeCertExpires.
	// We add a few seconds noise to the early renew period so that certificates that may have been
	// created at the same time are not renewed at the exact same time.
	intNoise := rand.Intn(noiseSeconds) // #nosec G404
	secondsNoise := time.Duration(intNoise) * time.Second
	renewBefore := RenewBeforeCertExpires + secondsNoise
	if time.Until(c.GetExpiration()) <= renewBefore {
		log.Info().Msgf("Cert %s should be rotated; expires in %+v; renewBefore is %+v",
			c.GetCommonName(),
			time.Until(c.GetExpiration()),
			renewBefore)
		return true
	}

	m.mu.RLock()
	validatingIssuer := m.validatingIssuer
	signingIssuer := m.signingIssuer
	m.mu.RUnlock()

	// During root certificate rotation the Issuers will change. If the Manager's Issuers are
	// different than the validating Issuer and signing Issuer IDs in the certificate, the
	// certificate must be reissued with the correct Issuers for the current rotation stage and
	// state. If there is no root certificate rotation in progress, the cert and Manager Issuers
	// will match.
	if c.signingIssuerID != signingIssuer.ID || c.validatingIssuerID != validatingIssuer.ID {
		log.Info().Msgf("Cert %s should be rotated; in progress root certificate rotation",
			c.GetCommonName())
		return true
	}
	return false
}

func (m *Manager) checkAndRotate() {
	// NOTE: checkAndRotate can reintroduce a certificate that has been released, thereby creating an unbounded cache.
	// A certificate can also have been rotated already, leaving the list of issued certs stale, and we re-rotate.
	// the latter is not a bug, but a source of inefficiency.
	for _, cert := range m.ListIssuedCertificates() {
		// Get existing or issue new certificate
		newCert, err := m.IssueCertificate(cert.GetCommonName(), cert.certType)
		if err != nil {
			// TODO(#3962): metric might not be scraped before process restart resulting from this error
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrRotatingCert)).
				Msgf("Error rotating cert SerialNumber=%s", cert.GetSerialNumber())
			continue
		}
		if newCert != cert {
			// Certificate was rotated
			m.msgBroker.GetCertPubSub().Pub(events.PubSubMessage{
				Kind:   announcements.CertificateRotated,
				NewObj: newCert,
				OldObj: cert,
			}, announcements.CertificateRotated.String())

			log.Debug().Msgf("Rotated certificate (old SerialNumber=%s) with new SerialNumber=%s", cert.SerialNumber, newCert.SerialNumber)
		}
	}
}

func (m *Manager) getValidityDurationForCertType(ct CertType) time.Duration {
	switch ct {
	case Internal:
		return constants.OSMCertificateValidityPeriod
	case IngressGateway:
		return m.ingressCertValidityDuration()
	case Service:
		return m.serviceCertValidityDuration()
	default:
		log.Debug().Msgf("Invalid certificate type provided when getting validity duration")
		return constants.OSMCertificateValidityPeriod
	}
}

func (m *Manager) getFromCache(cn CommonName) *Certificate {
	certInterface, exists := m.cache.Load(cn)
	if !exists {
		return nil
	}
	cert := certInterface.(*Certificate)
	log.Trace().Msgf("Certificate found in cache SerialNumber=%s", cert.GetSerialNumber())
	if m.shouldRotate(cert) {
		return nil
	}
	return cert
}

// IssueCertificate implements Manager and returns a newly issued certificate from the given client.
func (m *Manager) IssueCertificate(cn CommonName, ct CertType) (*Certificate, error) {
	var err error
	cert := m.getFromCache(cn) // Don't call this while holding the lock
	if cert != nil {
		return cert, nil
	}

	m.mu.RLock()
	validatingIssuer := m.validatingIssuer
	signingIssuer := m.signingIssuer
	m.mu.RUnlock()

	start := time.Now()
	validityDuration := m.getValidityDurationForCertType(ct)
	cert, err = signingIssuer.IssueCertificate(cn, validityDuration)
	if err != nil {
		return nil, err
	}

	// if we have different signing and validating issuers,
	// create the cert's trust context
	if validatingIssuer.ID != signingIssuer.ID {
		cert = cert.newMergedWithRoot(validatingIssuer.CertificateAuthority)
	}

	cert.signingIssuerID = signingIssuer.ID
	cert.validatingIssuerID = validatingIssuer.ID

	m.cache.Store(cn, cert)

	log.Trace().Msgf("It took %s to issue certificate with SerialNumber=%s", time.Since(start), cert.GetSerialNumber())

	return cert, nil
}

// ReleaseCertificate is called when a cert will no longer be needed and should be removed from the system.
func (m *Manager) ReleaseCertificate(cn CommonName) {
	log.Trace().Msgf("Releasing certificate %s", cn)
	m.cache.Delete(cn)
}

// ListIssuedCertificates implements CertificateDebugger interface and returns the list of issued certificates.
func (m *Manager) ListIssuedCertificates() []*Certificate {
	var certs []*Certificate
	m.cache.Range(func(cnInterface interface{}, certInterface interface{}) bool {
		certs = append(certs, certInterface.(*Certificate))
		return true // continue the iteration
	})
	return certs
}
