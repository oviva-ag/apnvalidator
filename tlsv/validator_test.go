package tlsv

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"testing"
)

func Test_loadPkcs12Certificate_tls_valid(t *testing.T) {

	data, err := ioutil.ReadFile("../cert.p12")
	if err != nil {
		log.Fatal(err)
	}

	var password = "1234"
	err = ValidateTlsHandshake(data, password)
	assert.NoError(t, err)
}

func Test_loadPkcs12Certificate_tls_revoked(t *testing.T) {

	data, err := ioutil.ReadFile("../cert_revoked.p12")
	if err != nil {
		log.Fatal(err)
	}

	var password = "1234"
	err = ValidateTlsHandshake(data, password)
	assert.Error(t, err)
}
