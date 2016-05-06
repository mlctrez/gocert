package server

import (
	"encoding/json"
	"fmt"
	"github.com/gocraft/web"
	"github.com/mlctrez/gocert/engine"
	"log"
	"net/http"
	"os"
)

// Context to pass information between middleware and handler.
type Context struct {
}

var (
	engineContext *engine.Context
)

// NewCert generates a new certificate based on the provided domain
// and returns the json payload containing the certificate and key.
func (c *Context) NewCert(rw web.ResponseWriter, req *web.Request) {

	response, err := engineContext.GenerateCertificate(req.PathParams["*"])
	if err != nil {
		panic(err)
	}

	rw.Header().Add("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(response)
}

// IndexPage just serves a simple OK response.
func (c *Context) IndexPage(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "OK")
}

// Main entry point for server
func Main(ctx *engine.Context) {
	engineContext = ctx
	web.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	router := web.New(Context{}).
		Middleware(web.LoggerMiddleware).
		Middleware(web.ShowErrorsMiddleware).
		Get("/", (*Context).IndexPage).
		Get("/newcert/:*", (*Context).NewCert)

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", router))
}
