package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gocraft/web"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

func generatePrivateKey(bits int) (privatekey *rsa.PrivateKey) {
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	return privatekey
}

func getSigningKey() (key *rsa.PrivateKey) {
	caPrivate, err := ioutil.ReadFile("registryCA.key")
	if err != nil {
		log.Fatal(err)
	}

	block, rest := pem.Decode(caPrivate)
	_ = block
	_ = rest

	key, er2 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if er2 != nil {
		log.Fatal(er2)
	}
	return
}

func getCAFile() (data []byte) {
	data, err := ioutil.ReadFile("registryCA.crt")
	if err != nil {
		log.Fatal(err)
	}
	return
}

func getCACertificate() (cert *x509.Certificate) {
	block, _ := pem.Decode(getCAFile())

	cert, er2 := x509.ParseCertificate(block.Bytes)
	if er2 != nil {
		log.Fatal(er2)
	}
	return
}

func generateSerial() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	return
}

func generateCertificate(domain string) (data ResponseData) {

	certprivate := generatePrivateKey(2048)
	certca := getCACertificate()
	certcaprivate := getSigningKey()

	serialNumber := generateSerial()

	notBefore := time.Now()
	notAfter := notBefore.Add(30 * 365 * 24 * time.Hour)

	subject := pkix.Name{
		CommonName: domain,
		Locality:   []string{"Saint Louis"},
		Province:   []string{"Missouri"},
		Country:    []string{"US"},
	}

	dnsnames := []string{domain, "*." + domain, strings.Split(domain, ".")[0]}

	template := x509.Certificate{
		IsCA:         false,
		SerialNumber: serialNumber,
		Subject:      subject,
		DNSNames:     dnsnames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}

	// template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, certca, &certprivate.PublicKey, certcaprivate)
	if err != nil {
		log.Fatalf("failed CreateCertificate: %s", err)
	}

	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	keyBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certprivate)}
	caBlock := pem.Block{Type: "CERTIFICATE", Bytes: getCAFile()}

	data = ResponseData{
		Domain:      domain,
		Certificate: string(pem.EncodeToMemory(&certBlock)),
		Key:         string(pem.EncodeToMemory(&keyBlock)),
		Registry:    string(pem.EncodeToMemory(&caBlock)),
	}

	return

}

// Context to pass information between middleware and handler.
type Context struct {
}

// ResponseData is used to serialize the json response
type ResponseData struct {
	Domain      string
	Key         string
	Certificate string

	Registry string
}

// NewCert generates a new certificate based on the provided domain
// and returns the json payload containing the certificate and key.
func (c *Context) NewCert(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Add("Content-Type", "application/json")
	// TODO: validate path parameter
	json.NewEncoder(rw).Encode(generateCertificate(req.PathParams["*"]))
}

// IndexPage just serves a simple OK response.
func (c *Context) IndexPage(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "OK")
}

func main() {
	router := web.New(Context{}).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Get("/", (*Context).IndexPage).
		Get("/newcert/:*", (*Context).NewCert)

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", router))
}
