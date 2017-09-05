package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"

	"golang.org/x/net/publicsuffix"

	"github.com/decred/politeia/politeiawww/api/v1"
)

var (
	host      = flag.String("h", "https://127.0.0.1:4443", "host")
	printJson = flag.Bool("json", false, "Print JSON")
)

type ctx struct {
	client *http.Client
	csrf   string
}

func newClient(skipVerify bool) (*ctx, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	return &ctx{client: &http.Client{
		Transport: tr,
		Jar:       jar,
	}}, nil
}

func (c *ctx) getCSRF() (*v1.Version, error) {
	r, err := c.client.Get(*host)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	var mw io.Writer
	var body bytes.Buffer
	if *printJson {
		mw = io.MultiWriter(&body, os.Stdout)
	} else {
		mw = io.MultiWriter(&body)
	}
	io.Copy(mw, r.Body)
	if *printJson {
		fmt.Printf("\n")
	}

	var v v1.Version
	err = json.Unmarshal(body.Bytes(), &v)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal version: %v", err)
	}

	c.csrf = r.Header.Get("X-Csrf-Token")

	return &v, nil
}

func (c *ctx) login(email, password string) (*v1.Version, error) {
	l := v1.Login{
		Email:    email,
		Password: password, // XXX SCRYPT THIS
	}
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaAPIRoute + v1.RouteLogin
	fmt.Printf("Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil, nil
}

func (c *ctx) secret() (*v1.Version, error) {
	l := v1.Login{}
	b, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaAPIRoute + v1.RouteSecret
	fmt.Printf("secret Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil, nil
}

func _main() error {
	flag.Parse()

	// Always hit / first for csrf token and obtain api version
	fmt.Printf("=== GET / ===\n")
	c, err := newClient(true)
	if err != nil {
		return err
	}
	version, err := c.getCSRF()
	if err != nil {
		return err
	}
	fmt.Printf("Version: %v\n", version.Version)
	fmt.Printf("Route  : %v\n", version.Route)
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Login
	fmt.Printf("=== POST /api/v1/login ===\n")
	_, err = c.login("moo", "blah")
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Secret
	fmt.Printf("=== POST /api/v1/secret ===\n")
	_, err = c.secret()
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
