package util

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
)

// NormalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func NormalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// NewClient returns a new http.Client instance
func NewClient(skipVerify bool, certFilename string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	if !skipVerify {
		cert, err := ioutil.ReadFile(certFilename)
		if err != nil {
			return nil, err
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cert)

		tlsConfig.RootCAs = certPool
	}

	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	}}, nil
}

// ConvertBodyToByteArray converts a response body into a byte array
// and optionally prints it to stdout.
func ConvertBodyToByteArray(r io.Reader, print bool) []byte {
	var mw io.Writer
	var body bytes.Buffer
	if print {
		mw = io.MultiWriter(&body, os.Stdout)
	} else {
		mw = io.MultiWriter(&body)
	}
	io.Copy(mw, r)
	if print {
		fmt.Printf("\n")
	}

	return body.Bytes()
}
