package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/decred/politeia/politeiawww/api/v1"
)

var (
	host      = flag.String("h", "https://127.0.0.1:4443", "host")
	printJson = flag.Bool("json", false, "Print JSON")
)

func newClient(skipVerify bool) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr}
}

func getCSRF(c *http.Client) (*v1.Version, []*http.Cookie, string, error) {
	r, err := c.Get(*host)
	if err != nil {
		return nil, nil, "", err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, nil, "", fmt.Errorf("HTTP Status: %v", r.StatusCode)
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
		return nil, nil, "",
			fmt.Errorf("Could node unmarshal version: %v", err)
	}

	csrfToken := r.Header.Get("X-Csrf-Token")

	return &v, r.Cookies(), csrfToken, nil
}

func login(c *http.Client, cookies []*http.Cookie, csrfToken, email, password string) (*v1.Version, error) {
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
	req.Header.Add("X-CSRF-Token", csrfToken)
	for _, cookie := range cookies {
		fmt.Printf("Cookie: %v %v\n", cookie.Name, cookie.Value)
		req.AddCookie(cookie)
	}
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil, nil
}

func _main() error {
	flag.Parse()

	// Always hit / first for csrf token and obtain api version
	fmt.Printf("=== GET / ===\n")
	c := newClient(true)
	version, cookies, csrfToken, err := getCSRF(c)
	if err != nil {
		return err
	}
	fmt.Printf("Version: %v\n", version.Version)
	fmt.Printf("Route  : %v\n", version.Route)
	fmt.Printf("CSRF   : %v\n", csrfToken)
	for _, cookie := range cookies {
		fmt.Printf("Cookie : %v %v\n", cookie.Name, cookie.Value)

	}

	// Login
	fmt.Printf("=== POST /api/v1/login ===\n")
	_, err = login(c, cookies, csrfToken, "moo", "blah")
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
