package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/mlctrez/gocert/utils"
	"io/ioutil"
	"log"
	"strings"
)

// Context contains the attributes that are used to generate certificates.
type Context struct {
	CertificateAuthority           *x509.Certificate
	CertificateAuthorityPrivateKey *rsa.PrivateKey
	PrivateKeyBitLength            int
}

// CertificateResponse is the result of a certificate generation request.
type CertificateResponse struct {
	CertificatePem          string `json:"crt_file"`
	CertificateKey          string `json:"key_file"`
	CertificateAuthorityPem string `json:"registry_ca"`
}

func (t *Context) loadCACertificate(filename string) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New(fmt.Sprintf("error loading CA certificate : %v", err))
	}
	block, _ := pem.Decode(file)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	t.CertificateAuthority = cert
	return nil
}

func (t *Context) loadCAPrivate(filename string) error {
	caFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return errors.New(fmt.Sprintf("error loading CA key : %v", err))
	}
	block, _ := pem.Decode(caFile)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	t.CertificateAuthorityPrivateKey = key
	return nil
}

func (t *Context) validateContext() {
	if t.CertificateAuthority == nil {
		log.Fatal("EngineContext.CertificateAuthority nil")
	}
	if t.CertificateAuthorityPrivateKey == nil {
		log.Fatal("EngineContext.CertificateAuthorityPrivateKey nil")
	}
}

// LoadCertificates reads the public and private keys for the certificate authority into the context.
func (t *Context) LoadCertificates(pub string, priv string) error {
	err := t.loadCACertificate(pub)
	if err != nil {
		return err
	}
	err = t.loadCAPrivate(priv)
	if err != nil {
		return err
	}
	return nil
}

// GenerateCertificate uses the certificate authority and private key to generate a certificate for the provided domain.
// The wildcard and short domain name are also added as subject alternative names.
func (t *Context) GenerateCertificate(domain string) (response *CertificateResponse, err error) {

	if !strings.Contains(domain, ".") {
		err = errors.New("domain must contain at least one dot")
		return
	}

	log.Println("generating certificate for " + domain)

	t.validateContext()
	response = new(CertificateResponse)

	certificateKey := utils.GenerateKey(t.PrivateKeyBitLength)

	publicKey := &certificateKey.PublicKey

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

	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment

	template.BasicConstraintsValid = true

	template.NotBefore, template.NotAfter = utils.DateRange(30)

	// TODO: handle client cert stuff
	// template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	derBytes, err := x509.CreateCertificate(rand.Reader, template, t.CertificateAuthority,
		publicKey, t.CertificateAuthorityPrivateKey)

	if err != nil {
		return
	}

	response.CertificatePem = utils.EncodePemString("CERTIFICATE", derBytes)
	response.CertificateKey = utils.EncodePemString("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(certificateKey))
	response.CertificateAuthorityPem = utils.EncodePemString("CERTIFICATE", t.CertificateAuthority.Raw)

	return

}
