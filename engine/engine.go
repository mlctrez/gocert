// Package engine provides a simplified interface to certificate generation
// provided by the standard package crypto/*
//
// Currently this package supports generation of certificates suitable
// for use in securing a web application.
//
package engine

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/mlctrez/gocert/utils"
	kserver "github.com/mlctrez/gokeyserve/server"
)

// Context contains the attributes that are used to generate certificates.
type Context struct {
	CertificateAuthority           *x509.Certificate
	CertificateAuthorityPrivateKey *rsa.PrivateKey
	PrivateKeyBitLength            int
	Development                    bool
	ListenAddress                  string
	DebugListenAddress             string
	KeyServer                      *kserver.GoKeyServer
}

// CertificateResponse is the result of a certificate generation request.
type CertificateResponse struct {
	CertificatePem          string `json:"crt_file" xml:",cdata"`
	CertificateKey          string `json:"key_file" xml:",cdata"`
	CertificateAuthorityPem string `json:"registry_ca" xml:",cdata"`
}

// WritePlain exports the cert, key, and CA as text to the writer.
func (c *CertificateResponse) WritePlain(w io.Writer) (err error) {

	buff := bytes.NewBufferString("# Certificate Information\n\n")

	buff.WriteString("\n## CertificatePem\n")
	buff.WriteString(c.CertificatePem)

	buff.WriteString("\n## CertificateKey\n")
	buff.WriteString(c.CertificateKey)

	buff.WriteString("\n## CertificateAuthorityPem\n")
	buff.WriteString(c.CertificateAuthorityPem)

	_, err = buff.WriteTo(w)

	return err
}

func (t *Context) loadCACertificate(filename string) error {
	block, _ := pem.Decode(utils.ReadFile(filename))
	cert, err := x509.ParseCertificate(block.Bytes)
	t.CertificateAuthority = cert
	return err
}

func (t *Context) loadCAPrivate(filename string) error {
	block, _ := pem.Decode(utils.ReadFile(filename))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	t.CertificateAuthorityPrivateKey = key
	return err
}

func (t *Context) validateContext() error {
	if t.CertificateAuthority == nil {
		return errors.New("EngineContext.CertificateAuthority nil")
	}
	if t.CertificateAuthorityPrivateKey == nil {
		return errors.New("EngineContext.CertificateAuthorityPrivateKey nil")
	}
	return nil
}

// LoadCertificates reads the public and private keys for the certificate authority into the context.
func (t *Context) LoadCertificates(pubfile string, privfile string) error {
	if err := t.loadCACertificate(pubfile); err != nil {
		return err
	}
	if err := t.loadCAPrivate(privfile); err != nil {
		return err
	}
	return nil
}

// GenerateCertificate uses the certificate authority and private key to generate a certificate for the provided domain.
// The wildcard and short domain name are also added as subject alternative names.
func (t *Context) GenerateCertificate(domain string, client bool) (response *CertificateResponse, err error) {

	if !strings.Contains(domain, ".") {
		err = errors.New("domain must contain at least one dot")
		return
	}

	log.Println("generating certificate for " + domain)

	if err = t.validateContext(); err != nil {
		return
	}
	response = &CertificateResponse{}

	certificateKey := t.KeyServer.GetGeneratedKey()

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

	if client {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

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
