package server

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/gocraft/web"
	"github.com/mlctrez/gocert/engine"
	keyserver "github.com/mlctrez/gokeyserve/server"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

import _ "expvar"         // only used when -development flag set
import _ "net/http/pprof" // only used when -development flag set

// Context to pass information between middleware and handler.
type Context struct {
}

var (
	engineContext *engine.Context
)

// NewCert generates a new certificate based on the provided domain
// and returns the json payload containing the certificate and key.
func (c *Context) NewCert(rw web.ResponseWriter, req *web.Request) {

	req.ParseForm()

	clientCert := req.FormValue("client") == "true"

	if response, err := engineContext.GenerateCertificate(req.PathParams["*"], clientCert); err != nil {
		panic(err)
	} else if err := sendResponse(response, rw, req); err != nil {
		panic(err)
	}

}

func sendResponse(response *engine.CertificateResponse, rw web.ResponseWriter, req *web.Request) (err error) {
	accept := strings.Split(req.Header.Get("Accept"), ",")

	switch accept[0] {

	case "text/plain", "text/html":
		rw.Header().Add("Content-Type", "text/plain")
		err = response.WritePlain(rw)
	case "application/json":
		rw.Header().Add("Content-Type", "application/json")
		err = json.NewEncoder(rw).Encode(response)
	case "text/xml", "application/xml":
		rw.Header().Add("Content-Type", "text/xml")
		err = xml.NewEncoder(rw).Encode(response)
	default:
		err = fmt.Errorf("unsupported accept content type: %s", accept[0])
	}
	return
}

// IndexPage just serves a simple OK response.
func (c *Context) IndexPage(rw web.ResponseWriter, req *web.Request) {
	rw.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(rw, "OK")
}

// Main entry point for server
func Main(ctx *engine.Context) {

	keyserver.Start(10*time.Minute, 2)

	engineContext = ctx
	web.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	router := web.New(Context{})
	router.Middleware(web.LoggerMiddleware)
	if ctx.Development {
		router.Middleware(web.ShowErrorsMiddleware)
	}
	if ctx.DebugListenAddress != "" {
		go func() {
			log.Println(http.ListenAndServe(ctx.DebugListenAddress, nil))
		}()
	}
	router.Get("/", (*Context).IndexPage)
	router.Get("/newcert/:*", (*Context).NewCert)

	log.Fatal(http.ListenAndServe(ctx.ListenAddress, router))
}
