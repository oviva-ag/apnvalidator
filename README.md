# Apple Push Notification Certificate Validator

`apnvalidator` is a CLI utility to validate APN and PushKit certificates.

## Quickstart

Prerequisites is a valid installation of Go with installed packages in the `PATH`.

```
~> go get -u github.com/oviva-ag/apnvalidator
~> ./apnvalidator --validate < yourcertificate.p12
```

## Usage:

```
~> ./apnvalidator --help
Usage of ./apnvalidator:
  -certificate string
    	pkcs12 encoded certificate file to validate or '-' for stdin (default "-")
  -password string
    	password for the certificate (default "1234")
  -validate
    	validates the certificate with all supported variants
  -validate-expiry
    	validate if the certificate is expired or not valid yet
  -validate-handshake
    	try to establish a TLS connection to the APN server
  -validate-revocation-list
    	validate if the certificate is in its revocation list
```



