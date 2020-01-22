package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiavoter/jsontypes"
	"github.com/decred/politeia/util"
	"golang.org/x/net/publicsuffix"
)

func usage() {

	fmt.Fprintf(os.Stderr, "usage: politeiavoteraudit\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "actions:\n")
	fmt.Fprintf(os.Stderr, "  list [hash]  - lists all vote hashes OR specified hash\n")
	fmt.Fprintf(os.Stderr, "  audit <hash> - audit vote hash\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// ctx is the client context.
type ctx struct {
	cfg *config // application config

	// https
	client    *http.Client
	id        *identity.PublicIdentity
	csrf      string
	userAgent string
}

func newClient(cfg *config) (*ctx, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial:            cfg.dial,
	}
	if cfg.Proxy != "" {
		tr.MaxConnsPerHost = 1
		tr.DisableKeepAlives = true
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	// return context
	return &ctx{
		cfg: cfg,
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		},
		userAgent: fmt.Sprintf("politeiavoteraudit/%s", cfg.Version),
	}, nil
}

func (c *ctx) getCSRF() (*v1.VersionReply, error) {
	requestBody, err := json.Marshal(v1.Version{})
	if err != nil {
		return nil, err
	}

	fullRoute := c.cfg.PoliteiaWWW + v1.PoliteiaWWWAPIRoute + v1.RouteVersion
	log.Debugf("Request: GET %v", fullRoute)

	log.Tracef("%v  ", string(requestBody))

	log.Debugf("Request: %v", fullRoute)
	req, err := http.NewRequest(http.MethodGet, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	log.Tracef("Response: %v", string(responseBody))
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
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	version, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	log.Debugf("Version: %v", version.Version)
	log.Debugf("Route  : %v", version.Route)
	log.Debugf("Pubkey : %v", version.PubKey)
	log.Debugf("CSRF   : %v", c.csrf)

	c.id, err = util.IdentityFromString(version.PubKey)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *ctx) list(args []string) error {
	// Display all vote hashes
	if len(args) == 0 {
		d, err := ioutil.ReadDir(c.cfg.voteDir)
		if err != nil {
			return err
		}

		for _, v := range d {
			fmt.Printf("%v\n", v.Name())
		}
		return nil
	}

	// Handle hashes
	for k, v := range args {
		d, err := ioutil.ReadDir(filepath.Join(c.cfg.voteDir, v))
		if err != nil {
			return err
		}

		fmt.Printf("%v\n", v)
		for _, vv := range d {
			fmt.Printf("  %v\n", vv.Name())
		}
		if k != len(args)-1 {
			fmt.Printf("\n")
		}
	}

	return nil
}

func readWork(filename string, m map[string]jsontypes.VoteInterval) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	// Read timestamp
	var timestamp jsontypes.Timestamp
	if err := d.Decode(&timestamp); err == io.EOF {
		return fmt.Errorf("expected timestamp")
	} else if err != nil {
		return err
	}

	// Read array
	var vi []jsontypes.VoteInterval
	if err := d.Decode(&vi); err == io.EOF {
		return fmt.Errorf("no votes in work log")
	} else if err != nil {
		return err
	}
	for _, v := range vi {
		m[v.Vote.Ticket] = v
	}

	return nil
}

func readSuccess(filename string, m map[string]jsontypes.BallotResult) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	first := true
	d := json.NewDecoder(f)
	for {
		// Read timestamp
		var timestamp jsontypes.Timestamp
		if err := d.Decode(&timestamp); err == io.EOF {
			if first {
				return fmt.Errorf("expected timestamp")
			}
			break
		} else if err != nil {
			return err
		}

		// Read array
		var br jsontypes.BallotResult
		if err := d.Decode(&br); err == io.EOF {
			return fmt.Errorf("no ballotresult in success log")
		} else if err != nil {
			return err
		}
		m[br.Ticket] = br
		fmt.Printf("%v\n", spew.Sdump(br))
		first = false
	}

	return nil
}

func (c *ctx) audit(args []string) error {
	for k, v := range args {
		path := filepath.Join(c.cfg.voteDir, v)
		d, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}

		work := make(map[string]jsontypes.VoteInterval, 1024)
		success := make(map[string]jsontypes.BallotResult, 1024)
		fmt.Printf("%v\n", v)
		for _, vv := range d {
			if c.cfg.Verbose {
				fmt.Printf("  %v\n", vv.Name())
			}

			filename := filepath.Join(path, vv.Name())

			var err error
			if strings.HasPrefix(vv.Name(), "work.") {
				// Read work
				err = readWork(filename, work)
			}

			if strings.HasPrefix(vv.Name(), "success.") {
				// Read success
				err = readSuccess(filename, success)
			}

			if strings.HasPrefix(vv.Name(), "failed.") {
				// Read success
				fmt.Printf("failed not yet\n")
			}

			if err != nil {
				return err
			}
		}
		//spew.Dump(work)

		// Don't print \n on the last entry
		if k != len(args)-1 {
			fmt.Printf("\n")
		}
	}

	return nil
}

func _main() error {
	cfg, args, err := loadConfig()
	if err != nil {
		return err
	}
	_ = cfg
	if len(args) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}
	action := args[0]

	//var seed int64
	//if action == "vote" {
	//	seed, err = generateSeed()
	//	if err != nil {
	//		return err
	//	}
	//}

	// Contact WWW
	c, err := firstContact(cfg)
	if err != nil {
		return err
	}
	// Close GRPC
	//defer c.conn.Close()

	//// Get block height to validate GRPC creds
	//ar, err := c.wallet.Accounts(c.wctx, &pb.AccountsRequest{})
	//if err != nil {
	//	return err
	//}
	//log.Debugf("Current wallet height: %v", ar.CurrentBlockHeight)

	//// Scan through command line arguments.

	switch action {
	case "list":
		err = c.list(args[1:])
	case "audit":
		err = c.audit(args[1:])
	default:
		err = fmt.Errorf("invalid action: %v", action)
	}

	return err
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
