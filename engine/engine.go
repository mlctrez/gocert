package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/mlctrez/gocert/utils"
	"io/ioutil"
	"log"
	"strings"
)

type EngineContext struct {
	CertificateAuthority           *x509.Certificate
	CertificateAuthorityPrivateKey *rsa.PrivateKey
	GeneratedCertificateBits       int
}

type CertificateResponse struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

func (t *EngineContext) LoadCACertificate(filename string) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(file)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	t.CertificateAuthority = cert
	return nil
}

func (t *EngineContext) LoadCAPrivate(filename string) error {
	caFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(caFile)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	t.CertificateAuthorityPrivateKey = key
	return nil
}

func (t *EngineContext) validateContext() {
	if t.CertificateAuthority == nil {
		log.Fatal("EngineContext.CertificateAuthority nil")
	}
	if t.CertificateAuthorityPrivateKey == nil {
		log.Fatal("EngineContext.CertificateAuthorityPrivateKey nil")
	}
}

func (t *EngineContext) GenCert(domain string) (response *CertificateResponse, err error) {

	t.validateContext()
	response = new(CertificateResponse)

	response.Key = utils.GenerateKey(t.GeneratedCertificateBits)

	subject := pkix.Name{
		CommonName: domain,
		Locality:   []string{"Saint Louis"},
		Province:   []string{"Missouri"},
		Country:    []string{"US"},
	}

	dnsnames := []string{domain}
	dnsnames = append(dnsnames, "*." + domain)
	dnsnames = append(dnsnames, strings.Split(domain, ".")[0])

	template := x509.Certificate{
		IsCA:         false,
		SerialNumber: utils.GenerateSerial(),
		Subject:      subject,
		DNSNames:     dnsnames,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}

	template.NotBefore, template.NotAfter = utils.DateRange(30)

	// TODO: handle client cert stuff
	// template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, t.CertificateAuthority, &response.Key.PublicKey, t.CertificateAuthorityPrivateKey)

	if err != nil {
		return
	}

	response.Certificate, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return
	}

	return

}
