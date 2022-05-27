package certificate

import (
	"testing"
	time "time"

	tassert "github.com/stretchr/testify/assert"

	"github.com/openservicemesh/osm/pkg/announcements"
	"github.com/openservicemesh/osm/pkg/certificate/pem"
	"github.com/openservicemesh/osm/pkg/messaging"
)

func TestRotor(t *testing.T) {
	assert := tassert.New(t)

	cn := CommonName("foo")
	validityPeriod := -1 * time.Hour // negative time means this cert has already expired -- will be rotated asap

	stop := make(chan struct{})
	defer close(stop)
	msgBroker := messaging.NewBroker(stop)
	certManager, err := NewManager(&fakeMRCClient{}, func() time.Duration { return validityPeriod }, msgBroker)
	certManager.Start(5*time.Second, stop)
	assert.NoError(err)

	certA, _, err := certManager.IssueCertificate(cn, validityPeriod, Service)
	assert.NoError(err)
	certRotateChan := msgBroker.GetCertPubSub().Sub(announcements.CertificateRotated.String())

	// Wait for two certificate rotations to be announced and terminate
	<-certRotateChan
	newCert, _, err := certManager.IssueCertificate(cn, validityPeriod, Service)
	assert.NoError(err)
	assert.NotEqual(certA.GetExpiration(), newCert.GetExpiration())
	assert.NotEqual(certA, newCert)
}

func TestShouldRotate(t *testing.T) {
	manager := &Manager{}

	testCases := []struct {
		name             string
		cert             *Certificate
		managerKeyIssuer *issuer
		managerPubIssuer *issuer
		expectedRotation bool
	}{
		{
			name: "Expired certificate",
			cert: &Certificate{
				Expiration:  time.Now().Add(-1 * time.Hour),
				keyIssuerID: "1",
				pubIssuerID: "1",
			},
			managerKeyIssuer: &issuer{ID: "1"},
			managerPubIssuer: &issuer{ID: "1"},
			expectedRotation: true,
		},
		{
			name: "Mismatched certificate",
			cert: &Certificate{
				Expiration:  time.Now().Add(1 * time.Hour),
				keyIssuerID: "1",
				pubIssuerID: "2",
			},
			managerKeyIssuer: &issuer{ID: "2"},
			managerPubIssuer: &issuer{ID: "1"},
			expectedRotation: true,
		},
		{
			name: "Valid certificate",
			cert: &Certificate{
				Expiration:  time.Now().Add(1 * time.Hour),
				keyIssuerID: "1",
				pubIssuerID: "1",
			},
			managerKeyIssuer: &issuer{ID: "1"},
			managerPubIssuer: &issuer{ID: "1"},
			expectedRotation: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := tassert.New(t)

			manager.keyIssuer = tc.managerKeyIssuer
			manager.pubIssuer = tc.managerPubIssuer

			rotate := manager.ShouldRotate(tc.cert)
			assert.Equal(tc.expectedRotation, rotate)
		})
	}
}

func TestReleaseCertificate(t *testing.T) {
	cn := CommonName("Test CN")
	cert := &Certificate{
		CommonName: cn,
		Expiration: time.Now().Add(1 * time.Hour),
	}

	manager := &Manager{}
	manager.cache.Store(cn, cert)

	testCases := []struct {
		name       string
		commonName CommonName
	}{
		{
			name:       "release existing certificate",
			commonName: cn,
		},
		{
			name:       "release non-existing certificate",
			commonName: cn,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := tassert.New(t)

			manager.ReleaseCertificate(tc.commonName)
			cert := manager.getFromCache(tc.commonName)

			assert.Nil(cert)
		})
	}
}

func TestListIssuedCertificate(t *testing.T) {
	assert := tassert.New(t)

	cn := CommonName("Test Cert")
	cert := &Certificate{
		CommonName: cn,
	}

	anotherCn := CommonName("Another Test Cert")
	anotherCert := &Certificate{
		CommonName: anotherCn,
	}

	expectedCertificates := []*Certificate{cert, anotherCert}

	manager := &Manager{}
	manager.cache.Store(cn, cert)
	manager.cache.Store(anotherCn, anotherCert)

	cs := manager.ListIssuedCertificates()
	assert.Len(cs, 2)

	for i, c := range cs {
		match := false
		for _, ec := range expectedCertificates {
			if c.GetCommonName() == ec.GetCommonName() {
				match = true
				assert.Equal(ec, c)
				break
			}
		}

		if !match {
			t.Fatalf("Certificate #%v %v does not exist", i, c.GetCommonName())
		}
	}
}

func TestIssueCertificate(t *testing.T) {
	cn := CommonName("fake-cert-cn")
	assert := tassert.New(t)
	certType := CertificateType("TEST")

	t.Run("single key issuer", func(t *testing.T) {
		cm := &Manager{
			// The root certificate signing all newly issued certificates
			keyIssuer: &issuer{ID: "id1", Issuer: &fakeIssuer{id: "id1"}},
			pubIssuer: &issuer{ID: "id1", Issuer: &fakeIssuer{id: "id1"}},
		}
		// single keyIssuer, not cached
		cert1, _, err := cm.IssueCertificate(cn, time.Minute, CertificateType("TEST"))
		assert.NoError(err)
		assert.NotNil(cert1)
		assert.Equal(cert1.keyIssuerID, "id1")
		assert.Equal(cert1.pubIssuerID, "id1")
		assert.Equal(cert1.GetIssuingCA(), pem.RootCertificate("id1"))

		// single keyIssuer cached
		cert2, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.Equal(cert1, cert2)

		// single key issuer, old version cached
		// TODO: could use informer logic to test mrc updates instead of just manually making changes.
		cm.keyIssuer = &issuer{ID: "id2", Issuer: &fakeIssuer{id: "id2"}}
		cm.pubIssuer = &issuer{ID: "id2", Issuer: &fakeIssuer{id: "id2"}}

		cert3, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotNil(cert3)
		assert.Equal(cert3.keyIssuerID, "id2")
		assert.Equal(cert3.pubIssuerID, "id2")
		assert.NotEqual(cert2, cert3)
		assert.Equal(cert3.GetIssuingCA(), pem.RootCertificate("id2"))
	})

	t.Run("2 issuers", func(t *testing.T) {
		cm := &Manager{
			// The root certificate signing all newly issued certificates
			keyIssuer: &issuer{ID: "id1", Issuer: &fakeIssuer{id: "id1"}},
			pubIssuer: &issuer{ID: "id2", Issuer: &fakeIssuer{id: "id2"}},
		}

		// Not cached
		cert1, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotNil(cert1)
		assert.Equal(cert1.keyIssuerID, "id1")
		assert.Equal(cert1.pubIssuerID, "id2")
		assert.Equal(cert1.GetIssuingCA(), pem.RootCertificate("id1id2"))

		// cached
		cert2, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.Equal(cert1, cert2)

		// cached, but pubIssuer is removed
		cm.pubIssuer = cm.keyIssuer
		cert3, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotEqual(cert1, cert3)
		assert.Equal(cert3.keyIssuerID, "id1")
		assert.Equal(cert3.pubIssuerID, "id1")
		assert.Equal(cert3.GetIssuingCA(), pem.RootCertificate("id1"))

		// cached, but keyIssuer is old
		cm.keyIssuer = &issuer{ID: "id2", Issuer: &fakeIssuer{id: "id2"}}
		cert4, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotEqual(cert3, cert4)
		assert.Equal(cert4.keyIssuerID, "id2")
		assert.Equal(cert4.pubIssuerID, "id1")
		assert.Equal(cert4.GetIssuingCA(), pem.RootCertificate("id2id1"))

		// cached, but pubIssuer is old
		cm.pubIssuer = &issuer{ID: "id3", Issuer: &fakeIssuer{id: "id3"}}
		cert5, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotEqual(cert4, cert5)
		assert.Equal(cert5.keyIssuerID, "id2")
		assert.Equal(cert5.pubIssuerID, "id3")
		assert.Equal(cert5.GetIssuingCA(), pem.RootCertificate("id2id3"))
	})

	t.Run("bad issuers", func(t *testing.T) {
		cm := &Manager{
			// The root certificate signing all newly issued certificates
			keyIssuer: &issuer{ID: "id1", Issuer: &fakeIssuer{id: "id1", err: true}},
			pubIssuer: &issuer{ID: "id2", Issuer: &fakeIssuer{id: "id2", err: true}},
		}

		// bad private key
		cert, _, err := cm.IssueCertificate(cn, time.Minute, certType)
		assert.Nil(cert)
		assert.EqualError(err, "id1 failed")

		// bad public key
		cm.keyIssuer = &issuer{ID: "id3", Issuer: &fakeIssuer{id: "id3"}}
		cert, _, err = cm.IssueCertificate(cn, time.Minute, certType)
		assert.Nil(cert)
		assert.EqualError(err, "id2 failed")

		// insert a cached cert
		cm.pubIssuer = cm.keyIssuer
		cert, _, err = cm.IssueCertificate(cn, time.Minute, certType)
		assert.NoError(err)
		assert.NotNil(cert)

		// bad public key on an existing cached cert, because the pubIssuer is new
		cm.pubIssuer = &issuer{ID: "id1", Issuer: &fakeIssuer{id: "id1", err: true}}
		cert, _, err = cm.IssueCertificate(cn, time.Minute, certType)
		assert.EqualError(err, "id1 failed")
		assert.Nil(cert)
	})
}
