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
	PrivateKeyBitLength            int
}

type CertificateResponse struct {
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey

	CertificatePem string
	CertificateKey string

	CertificateAuthority    *x509.Certificate
	CertificateAuthorityPem string
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

	response.Key = utils.GenerateKey(t.PrivateKeyBitLength)

	publicKey := &response.Key.PublicKey

	template := new(x509.Certificate)

	template.IsCA = false
	template.SerialNumber = utils.GenerateSerial()
	template.Subject = pkix.Name{
		CommonName: domain,
		Locality:   []string{"Saint Louis"},
		Province:   []string{"Missouri"},
		Country:    []string{"US"},
	}

	template.DNSNames = []string{domain, "*." + domain, strings.Split(domain, ".")[0]}

	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment

	template.BasicConstraintsValid = true

	template.NotBefore, template.NotAfter = utils.DateRange(30)

	// TODO: handle client cert stuff
	// template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	derBytes, err := x509.CreateCertificate(rand.Reader, template, t.CertificateAuthority,
		publicKey, t.CertificateAuthorityPrivateKey)

	if err != nil {
		return
	}

	response.Certificate, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return
	}

	response.CertificatePem = utils.EncodePemString("CERTIFICATE", derBytes)
	response.CertificateKey = utils.EncodePemString("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(response.Key))
	response.CertificateAuthority = t.CertificateAuthority
	response.CertificateAuthorityPem = utils.EncodePemString("CERTIFICATE", t.CertificateAuthority.Raw)

	return

}
