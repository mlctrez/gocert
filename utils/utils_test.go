package utils

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

const nsec = -time.Second
const psec = time.Second

func TestDateRange(t *testing.T) {
	stest, etest := DateRange(1)

	snow := time.Now().Add(nsec)
	if snow.After(stest) {
		t.Error("start time after now")
	}

	enow := stest.Add(365 * 24 * time.Hour)

	if etest.Before(enow.Add(nsec)) {
		t.Error("end time before expected")
	}
	if etest.After(enow.Add(psec)) {
		t.Error("end time before expected")
	}

}

func TestGenerateSerial(t *testing.T) {
	if GenerateSerial() == nil {
		t.Error("failed to generate serial")
	}
}

func TestReadFile(t *testing.T) {
	file, err := ioutil.TempFile("", "TestReadFile")
	if err != nil {
		t.Error("failed to create temp file for testing")
	}

	tdata := []byte{0, 1, 2}

	file.Write(tdata)
	file.Close()

	readData := ReadFile(file.Name())

	if os.Remove(file.Name()) != nil {
		t.Error("unable to remove file")
	}

	for i := 0; i < len(readData); i++ {
		if tdata[i] != readData[i] {
			t.Error("file comparison failure")
		}
	}

}

func TestEncodePemString(t *testing.T) {
	tdata := []byte{100, 100, 100, 100, 100, 100}
	certContents := EncodePemString("CERTIFICATE", tdata)
	expected := "-----BEGIN CERTIFICATE-----\nZGRkZGRk\n-----END CERTIFICATE-----\n"
	if certContents != expected {
		t.Error("did not get expected certificate text")
	}
}
