package main

import (
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
)

func main() {

	eng := new(engine.Context)
	eng.PrivateKeyBitLength = 2048

	err := eng.LoadCertificates("registryCA.crt", "registryCA.key")
	if err != nil {
		log.Fatal(err)
	}

	server.Main(eng)
}
