package crtv

import (
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"time"
)

// ValidateExpiry checks if a certificate is expired or not
func ValidateExpiry(pkcs12Bytes []byte, password string) error {

	from, to, err := ValidBetween(pkcs12Bytes, password)
	if err != nil {
		return err
	}

	now := time.Now()

	if now.After(to) {
		return fmt.Errorf("certificate expired at %s", to.Format(time.RFC3339))
	}

	if now.Before(from) {
		return fmt.Errorf("certificate not valid yet, valid after %s", from.Format(time.RFC3339))
	}

	return nil
}

// ValidateBetween returns the from and to timestamp where this certificate is valid
func ValidBetween(pkcs12Bytes []byte, password string) (from, to time.Time, err error) {

	_, certificate, err := pkcs12.Decode(pkcs12Bytes, password)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	from, to = validBetween(certificate)
	return from, to, nil
}

// ValidateExpiry checks if a certificate is expired or not
func validBetween(cert *x509.Certificate) (from, to time.Time) {
	return cert.NotBefore, cert.NotAfter
}
