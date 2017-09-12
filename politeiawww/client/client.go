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

func (c *ctx) newUser(email, password string) (string, error) {
	u := v1.NewUser{
		Email:    email,
		Password: password,
	}
	b, err := json.Marshal(u)
	if err != nil {
		return "", err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaWWWAPIRoute + v1.RouteNewUser
	fmt.Printf("Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP Status: %v", r.StatusCode)
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

	var nur v1.NewUserReply
	err = json.Unmarshal(body.Bytes(), &nur)
	if err != nil {
		return "", fmt.Errorf("Could node unmarshal NewUserReply: %v",
			err)
	}

	fmt.Printf("Verification Token: %v\n", nur.VerificationToken)
	return nur.VerificationToken, nil
}

func (c *ctx) verifyNewUser(email, token string) error {
	u := v1.VerifyNewUser{
		Email:             email,
		VerificationToken: token,
	}
	b, err := json.Marshal(u)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaWWWAPIRoute + v1.RouteVerifyNewUser
	fmt.Printf("Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil
}

func (c *ctx) login(email, password string) error {
	l := v1.Login{
		Email:    email,
		Password: password, // XXX SCRYPT THIS
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaWWWAPIRoute + v1.RouteLogin
	fmt.Printf("Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil
}

func (c *ctx) secret() error {
	l := v1.Login{}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaWWWAPIRoute + v1.RouteSecret
	fmt.Printf("secret Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil
}

func (c *ctx) logout() error {
	l := v1.Login{}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}

	if *printJson {
		fmt.Println(string(b))
	}
	route := *host + v1.PoliteiaWWWAPIRoute + v1.RouteLogout
	fmt.Printf("Route : %v\n", route)
	req, err := http.NewRequest("POST", route, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	return nil
}

func (c *ctx) assets() error {
	route := *host + "/static/" //v1.PoliteiaWWWAPIRoute + v1.RouteSecret
	fmt.Printf("asset Route : %v\n", route)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return err
	}
	req.Header.Add("X-CSRF-Token", c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	io.Copy(os.Stdout, r.Body)

	return nil
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

	// New User
	fmt.Printf("=== POST /api/v1/user/new ===\n")
	token, err := c.newUser("moo@moo.com", "sikrit!")
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Verify New User
	fmt.Printf("=== POST /api/v1/user/verify ===\n")
	err = c.verifyNewUser("moo@moo.com", token)
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Login
	fmt.Printf("=== POST /api/v1/login ===\n")
	err = c.login("moo@moo.com", "sikrit!")
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Secret
	fmt.Printf("=== POST /api/v1/secret ===\n")
	err = c.secret()
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Secret again
	fmt.Printf("=== POST /api/v1/secret ===\n")
	err = c.secret()
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Logout
	fmt.Printf("=== POST /api/v1/logout ===\n")
	err = c.logout()
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	fmt.Printf("=== GET assets ===\n")
	err = c.assets()
	if err != nil {
		return err
	}

	// Secret once more that should fail
	fmt.Printf("=== POST /api/v1/secret ===\n")
	err = c.secret()
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
