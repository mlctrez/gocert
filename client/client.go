package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// CertificateResponse is the result of a certificate generation request.
type CertificateResponse struct {
	CertificatePem          string `json:"crt_file" xml:",cdata"`
	CertificateKey          string `json:"key_file" xml:",cdata"`
	CertificateAuthorityPem string `json:"registry_ca" xml:",cdata"`
}

func (cr *CertificateResponse) Certificate() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(cr.CertificatePem), []byte(cr.CertificateKey))
}

func (cr *CertificateResponse) ClientTlsConfig() (config *tls.Config, err error) {

	certificate, err := cr.Certificate()
	if err != nil {
		return nil, err
	}

	config = &tls.Config{}

	config.Certificates = []tls.Certificate{certificate}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cr.CertificateAuthorityPem))

	config.RootCAs = caCertPool

	return config, nil

}

func (cr *CertificateResponse) ServerTlsConfig(clientCert bool) (config *tls.Config, err error) {

	certificate, err := cr.Certificate()
	if err != nil {
		return nil, err
	}

	config = &tls.Config{}

	config.Certificates = []tls.Certificate{certificate}

	if clientCert {
		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM([]byte(cr.CertificateAuthorityPem))

		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = clientCAs
	}

	return config, nil

}

func JsonRequest(url string, resp interface{}) error {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	request.Header["Accept"] = []string{"application/json"}

	httpResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, resp)
	return err
}

func CertificateRequest(name string, clientCert bool) (resp *CertificateResponse, err error) {

	resp = &CertificateResponse{}

	url := fmt.Sprintf("http://pp1:9999/newcert/%v?client=%v", name, clientCert)

	err = JsonRequest(url, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
