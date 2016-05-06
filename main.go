package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
	"os"
	"strings"
)

var fs = flag.NewFlagSet("gocert", flag.ContinueOnError)

func error(err interface{}) {

	if !strings.Contains(fmt.Sprintf("%v", err), "flag provided but not defined") {
		fmt.Println("Usage of gocert:")
		fs.PrintDefaults()
		fmt.Printf("\nERROR: %v\n", err)
	}

	os.Exit(1)
}

func main() {

	var caCert string
	var caKey string

	fs.StringVar(&caCert, "cacert", "", "Path to the Certificate Authority certificate")
	fs.StringVar(&caKey, "cakey", "", "Path to the Certificate Authority certificate private key")
	if err := fs.Parse(os.Args[1:]); err != nil {
		error(err)
	}

	if caCert == "" || caKey == "" {
		error(errors.New("both -cacert and -cakey are required"))
	}

	eng := new(engine.Context)
	eng.PrivateKeyBitLength = 2048

	if err := eng.LoadCertificates(caCert, caKey); err != nil {
		error(err)
	}

	log.Println("starting server")

	server.Main(eng)
}
