package crlv

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"testing"
)

func Test_loadPkcs12Certificate_crl_valid(t *testing.T) {

	data, err := ioutil.ReadFile("../cert.p12")
	if err != nil {
		log.Fatal(err)
	}

	var password = "1234"
	status, err := ValidateCrl(data, password)
	assert.NoError(t, err)
	assert.Equal(t, status, StatusValid)
}

func Test_loadPkcs12Certificate_crl_revoked(t *testing.T) {

	data, err := ioutil.ReadFile("../cert_revoked.p12")
	if err != nil {
		log.Fatal(err)
	}

	var password = "1234"
	status, err := ValidateCrl(data, password)
	assert.NoError(t, err)
	assert.Equal(t, status, StatusRevoked)
}
