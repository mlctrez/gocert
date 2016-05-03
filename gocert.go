package main

import (
	"github.com/mlctrez/gocert/engine"
	"github.com/mlctrez/gocert/server"
	"log"
)

func main() {

	eng := new(engine.EngineContext)
	eng.PrivateKeyBitLength = 2048

	err := eng.LoadCACertificate("registryCA.crt")
	if err != nil {
		log.Fatal(err)
	}

	err = eng.LoadCAPrivate("registryCA.key")
	if err != nil {
		log.Fatal(err)
	}

	server.Main(eng)
}
