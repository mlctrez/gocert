package main

import (
	"errors"
	"flag"
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
)

func main() {

	caCert := flag.String("cacert", "", "Path to the CA certificate")
	caKey := flag.String("cakey", "", "Path to the CA private key")

	development := flag.Bool("development", false, "Enables stack trace middleware")
	listen := flag.String("listen", ":8080", "listen address and port for the http server")
	debugListen := flag.String("dlisten", "", "listen address for the expvar and pprof http server")

	flag.Parse()

	if *caCert == "" || *caKey == "" {
		flag.PrintDefaults()
		log.Fatal(errors.New("both -cacert and -cakey are required"))
	}

	eng := new(engine.Context)
	eng.PrivateKeyBitLength = 2048
	eng.Development = *development
	eng.ListenAddress = *listen
	eng.DebugListenAddress = *debugListen

	if err := eng.LoadCertificates(*caCert, *caKey); err != nil {
		log.Fatal(err)
	}

	log.Println("starting server")

	server.Main(eng)
}
