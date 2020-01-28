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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiavoter/jsontypes"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
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
	log.Debugf("Request: %v %v", method, fullRoute)
	if len(requestBody) != 0 {
		log.Tracef("%v  ", string(requestBody))
	}

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, jsontypes.ErrRetry{
			At:  "c.client.Do(req)",
			Err: err,
		}
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	log.Tracef("Response: %v %v", r.StatusCode, string(responseBody))

	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil && ue.ErrorCode != 0 {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode],
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, jsontypes.ErrRetry{
			At:   "r.StatusCode != http.StatusOK",
			Err:  err,
			Body: responseBody,
			Code: r.StatusCode,
		}
	}

	return responseBody, nil
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

func readWork(verbose bool, filename string, m map[int64][]jsontypes.VoteInterval) error {
	if verbose {
		fmt.Printf("  Parsing: %v\n", filepath.Base(filename))
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	// Read timestamp
	var timestamp jsontypes.Timestamp
	if err := d.Decode(&timestamp); err == io.EOF {
		return fmt.Errorf("expected timestamp in work log")
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
	t, err := time.Parse(time.StampNano, timestamp.Time)
	if err != nil {
		return err
	}
	m[t.UnixNano()] = vi

	return nil
}

func readSuccess(verbose bool, filename string, m map[int64]jsontypes.BallotResult) error {
	if verbose {
		fmt.Printf("  Parsing: %v\n", filepath.Base(filename))
	}

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
				return fmt.Errorf("expected timestamp in " +
					"succes log")
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
		t, err := time.Parse(time.StampNano, timestamp.Time)
		if err != nil {
			return err
		}
		m[t.Unix()] = br

		//fmt.Printf("%v\n", spew.Sdump(br))
		first = false
	}

	return nil
}

// HackError is a hacked up ErrRetry where the Err field us an interface. We
// need this to read the various error types in.
type HackError struct {
	At   string      `json:"at"`   // where in the code
	Body []byte      `json:"body"` // http body if we have one
	Code int         `json:"code"` // http code
	Err  interface{} `json:"err"`  // underlying error
}

// BallotError is a tuple to reconstruct the 3 json objects in the journal.
type BallotError struct {
	Ballot v1.Ballot
	Error  HackError
}

func readFailed(verbose bool, filename string, m map[int64]BallotError) error {
	if verbose {
		fmt.Printf("  Parsing: %v\n", filepath.Base(filename))
	}

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
				return fmt.Errorf("expected timestamp in " +
					"failed log")
			}
			break
		} else if err != nil {
			return err
		}

		// Read Ballot
		var b v1.Ballot
		if err := d.Decode(&b); err == io.EOF {
			return fmt.Errorf("no ballot in failed log")
		} else if err != nil {
			return err
		}

		// Read ErrRetry
		var e HackError
		if err := d.Decode(&e); err == io.EOF {
			return fmt.Errorf("no errretry in failed log")
		} else if err != nil {
			return err
		}

		t, err := time.Parse(time.StampNano, timestamp.Time)
		if err != nil {
			return err
		}
		m[t.Unix()] = BallotError{
			Ballot: b,
			Error:  e,
		}

		//fmt.Printf("%v%v\n", spew.Sdump(b), spew.Sdump(e))
		first = false
	}

	return nil
}

func findSuccess(ticket string, m map[int64]jsontypes.BallotResult) bool {
	for _, v := range m {
		if v.Ticket != ticket {
			continue
		}
		return true
	}
	return false
}

func countSuccess(proposal, ticket string, m map[int64]jsontypes.BallotResult) int {
	var count int
	for _, v := range m {
		if v.Ticket != ticket {
			continue
		}
		count++
	}
	return count
}

func countFailed(proposal, ticket string, m map[int64]BallotError) int {
	var count int
	for _, v := range m {
		for _, vv := range v.Ballot.Votes {
			if !(vv.Token == proposal && vv.Ticket == ticket) {
				continue
			}
			count++
		}
	}
	return count
}

func findWork(ticket string, m map[int64][]jsontypes.VoteInterval) bool {
	for _, v := range m {
		for _, vv := range v {
			if ticket == vv.Vote.Ticket {
				return true
			}
		}
	}
	return false
}

func auditWork(verbose bool, work map[int64][]jsontypes.VoteInterval, success map[int64]jsontypes.BallotResult, failed map[int64]BallotError) (int, error) {
	if verbose {
		fmt.Printf("  Audit: work\n")
	}

	// Remove any duplicate entries from the work journals. Duplicate
	// entries can happen when the user restarts politeiavoter and a
	// new work journal is created.
	voteIntervals := make(map[string]jsontypes.VoteInterval, 10000) // [ticket]struct{}
	for _, journal := range work {
		for _, v := range journal {
			voteIntervals[v.Vote.Ticket] = v
		}
	}

	// Read all work items and ensure they made it to one of the success
	// files.
	var errorCount, successCount, totalRecords int
	for _, v := range voteIntervals {
		totalRecords++
		if verbose {
			fmt.Printf("    Checking ticket: %v\n",
				v.Vote.Ticket)
		}

		// Troll sucess
		s := countSuccess(v.Vote.Token, v.Vote.Ticket,
			success)
		if verbose {
			fmt.Printf("    Success           : %v\n", s)
		}
		if s != 1 {
			errorCount++
			fmt.Printf("    Unexpected success: "+
				"want %v got %v\n", 1, s)
		}

		// Troll failed
		f := countFailed(v.Vote.Token, v.Vote.Ticket, failed)
		if verbose {
			fmt.Printf("    Retries           : %v\n", f)
		}

		if s == 0 && f <= 0 {
			errorCount++
			fmt.Printf("    Unexpected failed : "+
				"want > 0 got %v\n", f)
		} else {
			successCount++
		}
	}
	if errorCount != 0 {
		return 0, fmt.Errorf("auditWork: unexpected number of "+
			"errors: %v", errorCount)
	}

	if successCount != totalRecords {
		return 0, fmt.Errorf("auditWork: unexpected totals: "+
			"got %v want %v", successCount, totalRecords)
	}

	// if we make it here, all work, despite retries, completed correctly.
	return totalRecords, nil
}

func auditFailed(verbose bool, work map[int64][]jsontypes.VoteInterval, success map[int64]jsontypes.BallotResult, failed map[int64]BallotError) (int, error) {
	// Go through all failed records and ensure thet they are non-fatal
	// failures.
	if verbose {
		fmt.Printf("  Audit: failed\n")
	}

	totalFailed := 0
	for _, v := range failed {
		for _, vv := range v.Ballot.Votes {
			ok := findSuccess(vv.Ticket, success)
			if !ok {
				return 0, fmt.Errorf("permanent error on: %v", vv.Ticket)
			}
			totalFailed++
		}
	}

	return totalFailed, nil
}

func findCastVote(ticket string, vrr *v1.VoteResultsReply) bool {
	for _, v := range vrr.CastVotes {
		if v.Ticket == ticket {
			return true
		}
	}
	return false
}

func auditSuccess(verbose bool, work map[int64][]jsontypes.VoteInterval, success map[int64]jsontypes.BallotResult, vrr *v1.VoteResultsReply) (int, error) {
	if verbose {
		fmt.Printf("  Audit: success\n")
	}

	totalSuccess := 0
	for _, v := range success {
		ok := findWork(v.Ticket, work)
		if !ok {
			return 0, fmt.Errorf("ticket not found in work map: %v",
				v.Ticket)
		}
		if v.Receipt.Error != "" {
			// We record duplicate votes in success so let's make
			// sure it voted.
			if ok := findCastVote(v.Ticket, vrr); !ok {
				return 0, fmt.Errorf("error in success: %v",
					v.Ticket)
			}
		}
		totalSuccess++
	}

	return totalSuccess, nil
}

func (c *ctx) getVoteResultsReply(token string) (*v1.VoteResultsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+"/votes", nil)
	if err != nil {
		return nil, err
	}

	var vrr v1.VoteResultsReply
	err = json.Unmarshal(responseBody, &vrr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"ProposalVotesReply: %v", err)
	}

	return &vrr, nil
}

func auditPi(verbose bool, vrr *v1.VoteResultsReply, success map[int64]jsontypes.BallotResult) (int, error) {
	if verbose {
		fmt.Printf("  Audit: politeia\n")
	}

	cvm := make(map[string]*v1.CastVote, len(vrr.CastVotes))
	for _, cv := range vrr.CastVotes {
		cvm[cv.Ticket] = &cv
	}

	votedSuccess := 0
	for _, s := range success {
		if _, ok := cvm[s.Ticket]; !ok {
			continue
		}
		votedSuccess++
	}

	if verbose {
		fmt.Printf("  Politeia succeful votes: %v\n", votedSuccess)
	}

	return votedSuccess, nil
}

func (c *ctx) audit(args []string) error {
	for k, v := range args {
		path := filepath.Join(c.cfg.voteDir, v)
		d, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}

		work := make(map[int64][]jsontypes.VoteInterval, 1024)  // [timestamp][]VoteInterval
		success := make(map[int64]jsontypes.BallotResult, 1024) // [timestamp]BallotResult
		failed := make(map[int64]BallotError, 1024)             // [timestamp]BallotError
		fmt.Printf("Proposal: %v\n", v)

		vrr, err := c.getVoteResultsReply(v)
		if err != nil {
			return err
		}
		//spew.Dump(vrr)

		for _, vv := range d {
			filename := filepath.Join(path, vv.Name())

			var err error
			if strings.HasPrefix(vv.Name(), "work.") {
				// Read work
				err = readWork(c.cfg.Verbose, filename, work)
			} else if strings.HasPrefix(vv.Name(), "success.") {
				// Read success
				err = readSuccess(c.cfg.Verbose, filename, success)
			} else if strings.HasPrefix(vv.Name(), "failed.") {
				// Read failed
				err = readFailed(c.cfg.Verbose, filename, failed)
			} else {
				continue
			}
			if err != nil {
				return err
			}
		}

		// Audit work
		total, err := auditWork(c.cfg.Verbose, work, success, failed)
		if err != nil {
			return err
		}
		fmt.Printf("Total votes %v\n", total)

		// Audit Pi results
		totalVoted, err := auditPi(c.cfg.Verbose, vrr, success)
		if err != nil {
			return err
		}
		if totalVoted != total {
			return fmt.Errorf("totalVoted != total in pi; "+
				"got %v want %v", totalVoted, total)
		}
		fmt.Printf("Successful votes in pi and journal %v\n", total)

		// Audit success
		totalSuccess, err := auditSuccess(c.cfg.Verbose, work, success, vrr)
		if err != nil {
			return err
		}
		fmt.Printf("All success votes exist in work map %v\n", totalSuccess)

		// Audit failed
		totalRetries, err := auditFailed(c.cfg.Verbose, work, success,
			failed)
		if err != nil {
			return err
		}
		fmt.Printf("All failed votes were successfully retried. Total "+
			"vote retries: %v\n", totalRetries)

		// Don't print \n on the last entry
		if k != len(args)-1 {
			fmt.Printf("\n")
		}
	}

	fmt.Printf("** AUDIT SUCCESSFULLY COMPLETED **\n")

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
