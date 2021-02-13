package crlv

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Status int

const (
	StatusRevoked Status = iota
	StatusValid
	StatusNone
)

// ValidateCrl validates a certificate against it's CRL distribution points
func ValidateCrl(pkcs12Bytes []byte, password string) (status Status, err error) {

	_, certificate, err := pkcs12.Decode(pkcs12Bytes, password)
	if err != nil {
		return StatusNone, err
	}

	if len(certificate.CRLDistributionPoints) == 0 {
		return StatusNone, nil
	}

	for _, crlUrl := range certificate.CRLDistributionPoints {
		log.Printf("validating CRL from: %s", crlUrl)
		status, err = isCertRevoked(certificate, crlUrl)
		if err != nil {
			return StatusNone, err
		} else if status == StatusRevoked {
			return StatusRevoked, nil
		}
	}

	return StatusValid, nil
}

// isCertRevoked checks if the provided certificate is revoked according to the given CRL url.
func isCertRevoked(cert *x509.Certificate, url string) (crlStatus Status, err error) {
	crl, err := fetchCRL(url)
	if err != nil {
		return StatusNone, fmt.Errorf("failed to fetch crl: %w", err)
	}

	log.Printf("validating CRL expiry")
	if crl.HasExpired(time.Now()) {
		return StatusNone, fmt.Errorf("crl is expired: %s", url)
	}

	log.Printf("validating CRL signature")
	err = validateCrlSignature(cert, crl)
	if err != nil {
		return StatusNone, err
	}

	log.Printf("search certificate serial in CRL")
	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			log.Printf("intermediate serial number match, '%s' is revoked.", revoked.SerialNumber)
			return StatusRevoked, nil
		}
	}

	return StatusValid, nil
}

// validateCrlSignature validates if the CRL for a given certificate has a valid signature.
func validateCrlSignature(cert *x509.Certificate, crl *pkix.CertificateList) error {

	issuer := fetchIssuer(cert)
	if issuer == nil {
		return nil
	}

	return issuer.CheckCRLSignature(crl)
}

// fetchCRL fetches and parses a CRL.
func fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(body)
}

// fetchIssuer fetches the issuing certificate for a given certificate.
func fetchIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		log.Printf("fetching issuer of %s at %s\n", cert.Subject.CommonName, issuingCert)
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

// fetchRemote fetches a certificate from a URL.
func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(in)
}
