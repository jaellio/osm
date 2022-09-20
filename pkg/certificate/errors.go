package certificate

import (
	"errors"
)

var errEncodeKey = errors.New("encode key")
var errEncodeCert = errors.New("encode cert")
var errMarshalPrivateKey = errors.New("marshal private key")
var errNoPrivateKeyInPEM = errors.New("no private Key in PEM")

// ErrNoCertificateInPEM is the error for no certificate in PEM
var ErrNoCertificateInPEM = errors.New("no certificate in PEM")

// All of the below errors should be returned by the StorageEngine for each described scenario. The errors may be
// wrapped

// ErrInvalidCertSecret is the error that should be returned if the secret is stored incorrectly in the underlying infra
var ErrInvalidCertSecret = errors.New("invalid secret for certificate")

// ErrSecretNotFound should be returned if the secret isn't present in the underlying infra, on a Get
var ErrSecretNotFound = errors.New("secret not found")

// ErrUnexpectedMRCStatusInReconciler is the error that should be returned if a MRC has an unexpected (not error)
// status in the MRC reconciliation loop
var ErrUnexpectedMRCStatusInReconciler = errors.New("unexpected MRC status in reconciler")

// ErrUnexpectedMRCStatusInReconciler is the error that should be returned if a MRC is in an error state
// in the MRC reconciliation loop
var ErrMRCErrorStatusInReconciler = errors.New("MRC error status in reconciler")
