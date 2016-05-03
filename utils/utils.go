package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

// GenerateKey creates a rsa.PrivateKey of bits length, terminating the process on error.
func GenerateKey(bits int) (privatekey *rsa.PrivateKey) {
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// ReadFile reads a file path into a byte array, terminating the process on error.
func ReadFile(filename string) (content []byte) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// GenerateSerial generates a serial number.
func GenerateSerial() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	return
}

// DateRange creates a date range from time.Now() to N years in the future.
func DateRange(years time.Duration) (notBefore time.Time, notAfter time.Time) {
	notBefore = time.Now()
	notAfter = notBefore.Add(years * 365 * 24 * time.Hour)
	return
}

// EncodePemString encodes a string from blockType and bytes.
func EncodePemString(blockType string, bytes []byte) string {
	block := pem.Block{Type: blockType, Bytes: bytes}
	return string(pem.EncodeToMemory(&block))
}
