// +build integration

package certinstall

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.uber.org/zap/zaptest"
)

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

func certCleanup(caSerialNumber *big.Int) error {
	javaPath := os.Getenv("JAVA_HOME")
	keytoolPath := filepath.Join(javaPath, "bin/keytool.exe")
	//exec keytool import
	//-delete -cacerts -storepass changeit -alias 146025
	argsdelete := []string{
		"-delete", "-noprompt", "-cacerts",
		"-storepass", "changeit",
		"-alias", caSerialNumber.String(),
	}

	// if not elevated, relaunch  with runas administrator
	admin, err := isAdmin()
	if err != nil {
		return err
	}
	if !admin {
		return errors.New("no admin right provided, can't delete certificate")
	}
	err = exec.Command(keytoolPath, argsdelete...).Run()
	if err != nil {
		return err
	}
	return nil
}

// C:\\Program Files\\OpenJDK\\jdk-13.0.2\\bin\\keytool.exe -importcert -noprompt -cacerts -keystore C:\\Program Files\\OpenJDK\\jdk-13.0.2\\lib\\security\\cacerts -storepass changeit -file C:\\Users\\iliec\\AppData\\Local\\Temp\\cacert.934052423.crt -alias 146025

func Test_JavaCertImporter(t *testing.T) {
	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}
	logger := zaptest.NewLogger(t)
	err = JavaCertImporter(logger, cert, cert.SerialNumber)
	if err != nil {
		t.Log("error with Java Cert Import " + err.Error())
		t.Fail()
	}
	//	teardown after the test
	err = certCleanup(cert.SerialNumber)
	if err != nil {
		t.Log("Test_JavaCertImporter teardown failed due to error", err)
	}
}

func Test_isFirefoxInstalled(t *testing.T) {
	logger := zaptest.NewLogger(t)
	if !isFirefoxInstalled(logger) {

		t.Fail()
	}
}

func Test_FirefoxCertImporter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}

	err = FirefoxCertImporter(logger, cert, cert.SerialNumber)
	if err != nil {
		t.Log("error with Firefox Cert Import " + err.Error())
		t.Fail()
	}

}

func Test_WindowStoreCertImporter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		t.Fatal("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("failed to parse certificate: " + err.Error())
	}

	err = WindowStoreCertImporter(logger, cert, cert.SerialNumber)
	if err != nil {
		t.Log("error with windows trust store Cert Import " + err.Error())
		t.Fail()
	}

}
