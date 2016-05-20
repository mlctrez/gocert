package main

import (
	"errors"
	"flag"
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
)

func main() {

	caCert := flag.String("cacert", "", "Path to the Certificate Authority certificate")
	caKey := flag.String("cakey", "", "Path to the Certificate Authority certificate private key")
	development := flag.Bool("development", false, "Enables stack trace middleware")

	flag.Parse()

	if *caCert == "" || *caKey == "" {
		flag.PrintDefaults()
		log.Fatal(errors.New("both -cacert and -cakey are required"))
	}

	eng := new(engine.Context)
	eng.PrivateKeyBitLength = 2048
	eng.Development = *development

	if err := eng.LoadCertificates(*caCert, *caKey); err != nil {
		log.Fatal(err)
	}

	log.Println("starting server")

	server.Main(eng)
}
