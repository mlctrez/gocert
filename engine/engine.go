package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/mlctrez/gocert/utils"
	"log"
	"strings"
)

func init() {
	log.Println("init in engine")
}

func getSigningKey() (key *rsa.PrivateKey) {
	caPrivate := utils.ReadFile("registryCA.key")

	block, _ := pem.Decode(caPrivate)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func getCABytes() []byte {
	caFile := utils.ReadFile("registryCA.crt")
	block, _ := pem.Decode(caFile)
	return block.Bytes
}

func getCACertificate() (cert *x509.Certificate) {

	cert, err := x509.ParseCertificate(getCABytes())
	if err != nil {
		log.Fatal(err)
	}
	return
}

// types for constructing pem.Block
const (
	cert = "CERTIFICATE"
	key  = "RSA PRIVATE KEY"
)

// CertResponse is used to serialize the json response.
type CertResponse struct {
	Domain      string
	Key         string
	Certificate string

	Registry string
}

// GenerateCertificate creates an SSL certificate for the provided domain.
func GenerateCertificate(domain string) CertResponse {

	certca := getCACertificate()
	certcaprivate := getSigningKey()

	certprivate := utils.GenerateKey(2048)

	subject := pkix.Name{
		CommonName: domain,
		Locality:   []string{"Saint Louis"},
		Province:   []string{"Missouri"},
		Country:    []string{"US"},
	}

	dnsnames := []string{domain, "*." + domain, strings.Split(domain, ".")[0]}

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

	// template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, certca, &certprivate.PublicKey, certcaprivate)
	if err != nil {
		log.Fatalf("failed CreateCertificate: %s", err)
	}

	//certBlock := pem.Block{Type: CERT, Bytes: derBytes}
	keyBlock := pem.Block{Type: key, Bytes: x509.MarshalPKCS1PrivateKey(certprivate)}

	return CertResponse{
		Domain:      domain,
		Certificate: utils.EncodePemString(cert, derBytes),
		Key:         string(pem.EncodeToMemory(&keyBlock)),
		Registry:    utils.EncodePemString(cert, getCABytes()),
	}

}
