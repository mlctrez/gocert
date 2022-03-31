package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gocraft/web"
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/utils"
)

import _ "expvar"         // only used when -development flag set
import _ "net/http/pprof" // only used when -development flag set

// Context to pass information between middleware and handler.
type Context struct {
	ec *engine.Context
}

// NewCert generates a new certificate based on the provided domain
// and returns the json payload containing the certificate and key.
func (c *Context) NewCert(rw web.ResponseWriter, req *web.Request) {

	req.ParseForm()

	clientCert := req.FormValue("client") == "true"

	log.Println("generating cert")
	var response *engine.CertificateResponse
	var err error
	if response, err = c.ec.GenerateCertificate(req.PathParams["*"], clientCert); err != nil {
		panic(err)
	}
	log.Println("sending cert")
	if err := sendResponse(response, rw, req); err != nil {
		panic(err)
	}
	log.Println("complete")

}

func sendResponse(response *engine.CertificateResponse, rw web.ResponseWriter, req *web.Request) (err error) {
	accept := strings.Split(req.Header.Get("Accept"), ",")

	switch accept[0] {
	case "application/json":
		rw.Header().Add("Content-Type", "application/json")
		err = json.NewEncoder(rw).Encode(response)
	case "text/xml", "application/xml":
		rw.Header().Add("Content-Type", "text/xml")
		err = xml.NewEncoder(rw).Encode(response)
	default:
		rw.Header().Add("Content-Type", "text/plain")
		err = response.WritePlain(rw)
	}
	return
}

// IndexPage just serves a simple OK response.
func (c *Context) IndexPage(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "OK")
}

// CertificateAuthority serves up the certificate authority
func (c *Context) CertificateAuthority(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	pemString := utils.EncodePemString("CERTIFICATE", c.ec.CertificateAuthority.Raw)
	_, _ = rw.Write([]byte(pemString))
}

// Main entry point for server
func Main(ctx *engine.Context) {

	web.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	router := web.New(Context{})
	router.Middleware(web.LoggerMiddleware)
	router.Middleware(func(c *Context, rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
		c.ec = ctx
		next(rw, req)
	})
	if ctx.Development {
		router.Middleware(web.ShowErrorsMiddleware)
	}
	if ctx.DebugListenAddress != "" {
		go func() {
			log.Println(http.ListenAndServe(ctx.DebugListenAddress, nil))
		}()
	}
	router.Get("/", (*Context).IndexPage)
	router.Get("/ca", (*Context).CertificateAuthority)
	router.Get("/newcert/:*", (*Context).NewCert)

	log.Fatal(http.ListenAndServe(ctx.ListenAddress, router))
}
