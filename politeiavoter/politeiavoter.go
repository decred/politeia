package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
)

var (
	verify = false // Validate server TLS certificate
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiavoter [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  inventory          - Retrieve active "+
		"votes\n")
	fmt.Fprintf(os.Stderr, "\n")
}

type ctx struct {
	client *http.Client
	cfg    *config
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
	return &ctx{
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		}}, nil
}

func (c *ctx) getCSRF() (*v1.VersionReply, error) {
	requestBody, err := json.Marshal(v1.Version{})
	if err != nil {
		return nil, err
	}

	fmt.Printf("Request: GET /\n")

	//if *printJson {
	//	fmt.Println("  " + string(requestBody))
	//}

	req, err := http.NewRequest(http.MethodGet, c.cfg.PoliteiaWWW,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	//if *printJson {
	//	fmt.Println("Response: " + string(responseBody) + "\n")
	//}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	var v v1.VersionReply
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	c.csrf = r.Header.Get(v1.CsrfToken)

	return &v, nil
}

func firstContact(cfg *config) (*ctx, error) {
	// Always hit / first for csrf token and obtain api version
	fmt.Printf("=== Start ===\n")
	c, err := newClient(true)
	if err != nil {
		return nil, err
	}
	c.cfg = cfg
	version, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Version: %v\n", version.Version)
	fmt.Printf("Route  : %v\n", version.Route)
	fmt.Printf("CSRF   : %v\n\n", c.csrf)

	return c, nil
}

func (c *ctx) makeRequest(method, route string, b interface{}) ([]byte, error) {
	var requestBody []byte
	var queryParams string
	if b != nil {
		if method == http.MethodGet {
			// GET requests don't have a request body; instead we will populate
			// the query params.
			form := url.Values{}
			err := schema.NewEncoder().Encode(b, form)
			if err != nil {
				return nil, err
			}

			queryParams = "?" + form.Encode()
		} else {
			var err error
			requestBody, err = json.Marshal(b)
			if err != nil {
				return nil, err
			}
		}
	}

	fullRoute := c.cfg.PoliteiaWWW + v1.PoliteiaWWWAPIRoute + route +
		queryParams
	fmt.Printf("Request: %v %v\n", method, v1.PoliteiaWWWAPIRoute+route+
		queryParams)

	//if *printJson {
	//	fmt.Println("  " + string(requestBody))
	//}

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	//if *printJson {
	//	fmt.Printf("Response: %v %v\n\n", r.StatusCode, string(responseBody))
	//}
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode],
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	return responseBody, nil
}

func (c *ctx) _inventory() (*v1.PolicyReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal PolicyReply: %v",
			err)
	}

	return &pr, nil
}

func (c *ctx) inventory() error {
	i, err := c._inventory()
	if err != nil {
		return err
	}

	_ = i

	return nil
}

func _main() error {
	cfg, args, err := loadConfig()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}

	// Contact WWW
	c, err := firstContact(cfg)
	if err != nil {
		return err
	}

	// Scan through command line arguments.
	for i, a := range args {
		// Select action
		if i == 0 {
			switch a {
			case "inventory":
				return c.inventory()
			default:
				return fmt.Errorf("invalid action: %v", a)
			}
		}
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
