package tlsv

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"log"
	"net"
	"time"
)

const (
	pemTypeCertificate   = "CERTIFICATE"
	pemTypePrivateKey    = "PRIVATE KEY"
	apnPushApiServerName = "api.push.apple.com"
	apnPushApiAddr       = "api.push.apple.com:443"
)

func ValidateTlsHandshake(pkcs12Bytes []byte, password string) error {
	priv, pub, err := decodePkcs12Certificate(pkcs12Bytes, password)
	if err != nil {
		return err
	}

	cert := tls.Certificate{Certificate: [][]byte{pub}, PrivateKey: priv}
	tlsConfig := &tls.Config{
		ServerName:   apnPushApiServerName,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http"},
	}

	conn, err := net.DialTimeout("tcp", apnPushApiAddr, time.Second*3)
	defer conn.Close()
	if err != nil {
		return err
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		return err
	}

	if !tlsConn.ConnectionState().HandshakeComplete {
		return fmt.Errorf("handshake not complete")
	}

	err = checkForPendingAlerts(tlsConn)
	if err != nil {
		return err
	}

	return nil
}

func checkForPendingAlerts(conn *tls.Conn) error {
	// we need to read a few bytes in order to get any pending 'alerts'

	// give the Read() a moment to receive any pending alerts
	deadline := time.Now().Add(time.Second)
	err := conn.SetDeadline(deadline)
	if err != nil {
		return err
	}

	// this should time out or directly return any alerts in form of an error
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err != nil && !isTimeout(err) {
		return err
	}
	return nil
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	if ok && netErr.Timeout() == true {
		return true
	}
	return false
}

func decodePkcs12Certificate(data []byte, password string) (*rsa.PrivateKey, []byte, error) {
	pem, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, nil, err
	}
	var pub []byte
	var priv *rsa.PrivateKey
	for _, b := range pem {
		if b.Type == pemTypeCertificate {
			pub = b.Bytes
		} else if b.Type == pemTypePrivateKey {
			//pub = b.Bytes
			priv, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, nil, err
			}
		} else {
			log.Printf("unknown pem type: " + b.Type)
		}
	}
	return priv, pub, nil
}
