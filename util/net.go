package util

import "net"
import "net/http"
import "crypto/tls"
import "io"
import "bytes"
import "os"
import "fmt"

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
func NewClient(skipVerify bool) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr}
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
