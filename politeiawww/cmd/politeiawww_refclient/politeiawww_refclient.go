package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"

	"golang.org/x/net/publicsuffix"

	v1d "github.com/decred/politeia/politeiad/api/v1"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
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

func (c *ctx) makeRequest(method string, route string, b interface{}) ([]byte, error) {
	var requestBody []byte
	if b != nil {
		var err error
		requestBody, err = json.Marshal(b)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := *host + v1w.PoliteiaWWWAPIRoute + route
	fmt.Printf("Request: %v %v\n", method, v1w.PoliteiaWWWAPIRoute+route)

	if *printJson {
		fmt.Println(string(requestBody))
	}

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1w.CsrfToken, c.csrf)
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

	responseBody := util.ConvertBodyToByteArray(r.Body, *printJson)
	return responseBody, nil
}

func (c *ctx) getCSRF() (*v1w.Version, error) {
	r, err := c.client.Get(*host)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, *printJson)

	var v v1w.Version
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	c.csrf = r.Header.Get(v1w.CsrfToken)

	return &v, nil
}

func (c *ctx) policy() error {
	_, err := c.makeRequest("GET", v1w.RoutePolicy, nil)
	return err
}

func (c *ctx) newUser(email, password string) (string, error) {
	u := v1w.NewUser{
		Email:    email,
		Password: password,
	}

	responseBody, err := c.makeRequest("POST", v1w.RouteNewUser, u)
	if err != nil {
		return "", err
	}

	var nur v1w.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return "", fmt.Errorf("Could not unmarshal NewUserReply: %v",
			err)
	}

	fmt.Printf("Verification Token: %v\n", nur.VerificationToken)
	return nur.VerificationToken, nil
}

func (c *ctx) verifyNewUser(email, token string) error {
	u := v1w.VerifyNewUser{
		Email:             email,
		VerificationToken: token,
	}

	_, err := c.makeRequest("POST", v1w.RouteVerifyNewUser, u)
	if err != nil {
		return err
	}

	return nil
}

func (c *ctx) login(email, password string) error {
	l := v1w.Login{
		Email:    email,
		Password: password, // XXX SCRYPT THIS
	}

	_, err := c.makeRequest("POST", v1w.RouteLogin, l)
	if err != nil {
		return err
	}

	return nil
}

func (c *ctx) secret() error {
	l := v1w.Login{}
	_, err := c.makeRequest("POST", v1w.RouteSecret, l)
	if err != nil {
		return err
	}

	return nil
}

func (c *ctx) newProposal() error {
	np := v1w.NewProposal{
		Name:  "test",
		Files: make([]v1d.File, 0, 0),
	}

	np.Files = append(np.Files, v1d.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Payload: base64.StdEncoding.EncodeToString([]byte("This is a description")),
	})

	responseBody, err := c.makeRequest("POST", v1w.RouteNewProposal, np)
	if err != nil {
		return err
	}

	var vr v1w.NewProposalReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal NewProposalReply: %v",
			err)
	}

	return nil
}

func (c *ctx) allVetted() error {
	responseBody, err := c.makeRequest("GET", v1w.RouteAllVetted, nil)
	if err != nil {
		return err
	}

	var vr v1w.GetAllVettedReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetAllVettedReply: %v",
			err)
	}

	return nil
}

func (c *ctx) allUnvetted() error {
	responseBody, err := c.makeRequest("GET", v1w.RouteAllUnvetted, nil)
	if err != nil {
		return err
	}

	var ur v1w.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetAllUnvettedReply: %v",
			err)
	}

	return nil
}

func (c *ctx) logout() error {
	l := v1w.Login{}
	_, err := c.makeRequest("POST", v1w.RouteLogout, l)
	if err != nil {
		return err
	}

	return nil
}

func (c *ctx) assets() error {
	route := *host + "/static/" //v1w.PoliteiaWWWAPIRoute + v1w.RouteSecret
	fmt.Printf("asset Route : %v\n", route)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return err
	}
	req.Header.Add(v1w.CsrfToken, c.csrf)
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

	b, err := util.Random(8)
	if err != nil {
		return err
	}
	email := hex.EncodeToString(b) + "@example.com"
	password := hex.EncodeToString(b)

	// Policy
	err = c.policy()
	if err != nil {
		return err
	}

	// New User
	token, err := c.newUser(email, password)
	if err != nil {
		return err
	}

	// Verify New User
	err = c.verifyNewUser(email, token)
	if err != nil {
		return err
	}

	// New proposal
	err = c.newProposal()
	if err == nil {
		return fmt.Errorf("/new should only be accessible by logged in users")
	}

	// Login
	err = c.login(email, password)
	if err != nil {
		return err
	}

	// Secret
	err = c.secret()
	if err != nil {
		return err
	}

	// New proposal
	err = c.newProposal()
	if err != nil {
		return err
	}

	// Unvetted proposals
	err = c.allUnvetted()
	if err == nil {
		return fmt.Errorf("/unvetted should only be accessible by admin users")
	}

	// Vetted proposals
	err = c.allVetted()
	if err != nil {
		return err
	}

	// Logout
	err = c.logout()
	if err != nil {
		return err
	}
	fmt.Printf("CSRF   : %v\n", c.csrf)

	// Assets
	err = c.assets()
	if err != nil {
		return err
	}

	// Secret once more that should fail
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
