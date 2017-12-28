package main

import (
	"errors"
	"flag"
	"log"
	"time"

	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	kserver "github.com/mlctrez/gokeyserve/server"
)

func main() {

	listen := flag.String("listen", ":9999", "listen address and port for the http server")
	caCert := flag.String("cacert", "", "Path to the CA certificate")
	caKey := flag.String("cakey", "", "Path to the CA private key")

	development := flag.Bool("development", false, "Enables stack trace middleware")
	debugListen := flag.String("dlisten", "", "listen address for the expvar and pprof http server")

	flag.Parse()

	if *caCert == "" || *caKey == "" {
		flag.PrintDefaults()
		log.Fatal(errors.New("both -cacert and -cakey are required"))
	}

	ks, err := kserver.New(10*60*time.Second, 2)
	if err != nil {
		log.Fatalln(err)
	}

	ec := &engine.Context{
		PrivateKeyBitLength: 2048,
		Development:         *development,
		ListenAddress:       *listen,
		DebugListenAddress:  *debugListen,
		KeyServer:           ks,
	}

	if err := ec.LoadCertificates(*caCert, *caKey); err != nil {
		log.Fatal(err)
	}

	log.Println("starting server")

	server.Main(ec)
}
