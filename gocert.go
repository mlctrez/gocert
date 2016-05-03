package main

import (
	"github.com/mlctrez/gocert/engine"
	"log"
	"github.com/mlctrez/gocert/utils"
	"io/ioutil"
	"crypto/x509"
)

func main() {

	eng := new(engine.EngineContext)
	eng.GeneratedCertificateBits = 2048

	err := eng.LoadCACertificate("registryCA.crt")
	if err != nil {
		log.Fatal(err)
	}

	err = eng.LoadCAPrivate("registryCA.key")
	if err != nil {
		log.Fatal(err)
	}

	certResponse, err := eng.GenCert("foo.bar")
	if err != nil {
		log.Fatal(err)
	}

	certPem := utils.EncodePemString("CERTIFICATE", certResponse.Certificate.Raw)
	certKey := utils.EncodePemString("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(certResponse.Key))

	err = ioutil.WriteFile("testCert.crt", []byte(certPem), 0700)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("testCert.key", []byte(certKey), 0700)
	if err != nil {
		log.Fatal(err)
	}

}
