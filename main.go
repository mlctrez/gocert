package main

import (
	"flag"
	"fmt"
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
	"os"
)

func main() {

	fs := flag.NewFlagSet("gocert", flag.ContinueOnError)

	var caCert string
	var caKey string

	fs.StringVar(&caCert, "cacert", "", "Path to the Certificate Authority certificate")
	fs.StringVar(&caKey, "cakey", "", "Path to the Certificate Authority certificate private key")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	eng := new(engine.Context)
	eng.PrivateKeyBitLength = 2048

	err = eng.LoadCertificates(caCert, caKey)
	if err != nil {
		fs.PrintDefaults()
		fmt.Println(err)
		os.Exit(1)
	}

	log.Println("starting server")

	server.Main(eng)
}
