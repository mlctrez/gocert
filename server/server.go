package server

import (
	"encoding/json"
	"fmt"
	"github.com/gocraft/web"
	"github.com/mlctrez/gocert/engine"
	"log"
	"net/http"
)

// Context to pass information between middleware and handler.
type Context struct {
}

var (
	caCertificate string
	caKey         string
)

// NewCert generates a new certificate based on the provided domain
// and returns the json payload containing the certificate and key.
func (c *Context) NewCert(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Add("Content-Type", "application/json")

	response := engine.GenerateCertificate(req.PathParams["*"])

	json.NewEncoder(rw).Encode(response)
}

// IndexPage just serves a simple OK response.
func (c *Context) IndexPage(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "OK")
}

// Main entry point for server
func Main() {
	router := web.New(Context{}).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Get("/", (*Context).IndexPage).
		Get("/newcert/:*", (*Context).NewCert)

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", router))
}
