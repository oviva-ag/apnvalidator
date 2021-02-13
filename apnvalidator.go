package main

import (
	"flag"
	"fmt"
	"github.com/oviva-ag/apnvalidator/crlv"
	"github.com/oviva-ag/apnvalidator/crtv"
	"github.com/oviva-ag/apnvalidator/tlsv"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	var filenameOrStdin string
	flag.StringVar(&filenameOrStdin, "certificate", "-", "pkcs12 encoded certificate file to validate or '-' for stdin")

	var password string
	flag.StringVar(&password, "password", "1234", "password for the certificate")

	var validate, handshake, expiry, revocationList bool
	flag.BoolVar(&expiry, "validate-expiry", false, "validate if the certificate is expired or not valid yet")
	flag.BoolVar(&handshake, "validate-handshake", false, "try to establish a TLS connection to the APN server")
	flag.BoolVar(&revocationList, "validate-revocation-list", false, "validate if the certificate is in its revocation list")
	flag.BoolVar(&validate, "validate", false, "validates the certificate with all supported variants")

	flag.Parse()

	if validate {
		expiry = true
		handshake = true
		revocationList = true
	}

	data, err := loadCertificateData(filenameOrStdin)
	if err != nil {
		log.Fatal(err)
	}

	if expiry {
		mustNotBeExpired(data, password)
	}
	if handshake {
		mustSucceedTlsHanshake(data, password)
	}
	if revocationList {
		mustNotBeInCrl(data, password)
	}
}

func mustNotBeExpired(pkcs12Bytes []byte, password string) {
	log.Println("validating expiry dates")
	err := crtv.ValidateExpiry(pkcs12Bytes, password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("expiry dates OK")
}

func mustSucceedTlsHanshake(pkcs12Bytes []byte, password string) {
	log.Println("validating TLS handshake")
	err := tlsv.ValidateTlsHandshake(pkcs12Bytes, password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TLS handshake OK")
}
func mustNotBeInCrl(pkcs12Bytes []byte, password string) {
	log.Println("validating against Certificate Revocation List")
	err := validateAgainstCrl(pkcs12Bytes, password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("certificate revocation OK")
}

func loadCertificateData(filenameOrStdin string) (data []byte, err error) {

	if filenameOrStdin == "-" {
		return ioutil.ReadAll(os.Stdin)
	}

	return ioutil.ReadFile(filenameOrStdin)
}

func validateAgainstCrl(pkcs12Bytes []byte, password string) error {

	status, err := crlv.ValidateCrl(pkcs12Bytes, password)
	if err != nil {
		return err
	}

	if status == crlv.StatusRevoked {
		return fmt.Errorf("certificate revocation status is REVOKED")
	}

	if status == crlv.StatusValid || status == crlv.StatusNone {
		return nil
	}
	return fmt.Errorf("unknown revocation status: %d", status)
}
