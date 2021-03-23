// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
	"time"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/gorilla/schema"
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

// NewHTTPClient returns a new http Client.
func NewHTTPClient(skipVerify bool, certPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	if !skipVerify && certPath != "" {
		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		certPool, err := x509.SystemCertPool()
		if err != nil {
			fmt.Printf("WARN: unable to get system cert pool: %v\n", err)
			certPool = x509.NewCertPool()
		}
		certPool.AppendCertsFromPEM(cert)
		tlsConfig.RootCAs = certPool
	}

	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			IdleConnTimeout:       2 * time.Minute,
			ResponseHeaderTimeout: 2 * time.Minute,
			TLSClientConfig:       tlsConfig,
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

// ParseGetParams parses the query params from the GET request into a struct.
// This method requires the struct type to be defined with `schema` tags.
func ParseGetParams(r *http.Request, dst interface{}) error {
	err := r.ParseForm()
	if err != nil {
		return err
	}

	return schema.NewDecoder().Decode(dst, r.Form)
}

// RespBody returns the response body as a byte slice.
func RespBody(r *http.Response) []byte {
	var mw io.Writer
	var body bytes.Buffer
	mw = io.MultiWriter(&body)
	io.Copy(mw, r.Body)
	return body.Bytes()
}

// RemoteAddr returns a string of the remote address, i.e. the address that
// sent the request.
func RemoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(pdv1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}
