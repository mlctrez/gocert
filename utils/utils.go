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

// GenerateKey creates a rsa.PrivateKey of bits length or returns nil on error.
func GenerateKey(bits int) (privatekey *rsa.PrivateKey) {
	privatekey, _ = rsa.GenerateKey(rand.Reader, bits)
	return privatekey
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
	// serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	return
}

// DateRange is used to generate a date range of years, suitable for use on certificates.
func DateRange(years time.Duration) (notBefore time.Time, notAfter time.Time) {
	notBefore = time.Now()
	notAfter = notBefore.Add(years * 365 * 24 * time.Hour)
	return
}

// EncodePemString is a shorthand method for encoding a byte array into pem
// format, using the blockType as the header and footer.
func EncodePemString(blockType string, bytes []byte) string {
	block := pem.Block{Type: blockType, Bytes: bytes}
	return string(pem.EncodeToMemory(&block))
}
