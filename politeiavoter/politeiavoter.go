package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/decred/dcrd/chaincfg/chainhash"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	fmt.Fprintf(os.Stderr, "  vote               - Vote on a proposal\n")
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

	log.Debugf("Request: GET /")

	log.Tracef("%v  ", string(requestBody))

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
	c, err := newClient(true)
	if err != nil {
		return nil, err
	}
	c.cfg = cfg
	version, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	log.Debugf("Version: %v", version.Version)
	log.Debugf("Route  : %v", version.Route)
	log.Debugf("CSRF   : %v", c.csrf)

	return c, nil
}

func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		hh, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hh[:])
	}
	return hashes, nil
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
	log.Debugf("Request: %v %v", method, v1.PoliteiaWWWAPIRoute+route+
		queryParams)
	if len(requestBody) != 0 {
		log.Tracef("%v  ", string(requestBody))
	}

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
	log.Tracef("Response: %v %v", r.StatusCode, string(responseBody))
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

func (c *ctx) _inventory() (*v1.ActiveVoteReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteActiveVote, nil)
	if err != nil {
		return nil, err
	}

	var ar v1.ActiveVoteReply
	err = json.Unmarshal(responseBody, &ar)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ActiveVoteReply: %v",
			err)
	}

	return &ar, nil
}

func (c *ctx) inventory() error {
	i, err := c._inventory()
	if err != nil {
		return err
	}

	// Setup GRPC
	ctx := context.Background()
	creds, err := credentials.NewClientTLSFromFile(c.cfg.WalletCert,
		"localhost")
	if err != nil {
		return err
	}
	conn, err := grpc.Dial("127.0.0.1:19111", grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := pb.NewWalletServiceClient(conn)

	// Get latest block
	ar, err := client.Accounts(ctx, &pb.AccountsRequest{})
	if err != nil {
		return err
	}
	latestBlock := ar.CurrentBlockHeight
	// fmt.Printf("Current block: %v\n", latestBlock)

	for _, v := range i.Votes {
		// Make sure we have a CensorshipRecord
		if v.Proposal.CensorshipRecord.Token == "" {
			// This should not happen
			log.Debugf("skipping empty CensorshipRecord")
			continue
		}

		// Make sure we have valid vote bits
		if v.Vote.Token == "" || v.Vote.Mask == 0 ||
			v.Vote.Options == nil {
			// This should not happen
			log.Debugf("invalid vote bits: %v",
				v.Proposal.CensorshipRecord.Token)
			continue
		}

		// Sanity, check if vote has expired
		endHeight, err := strconv.ParseInt(v.VoteDetails.EndHeight, 10, 32)
		if err != nil {
			return err
		}
		if int64(latestBlock) > endHeight {
			// Should not happen
			fmt.Printf("Vote expired: current %v > end %v %v\n",
				endHeight, latestBlock, v.Vote.Token)
			continue
		}

		// Ensure eligibility
		//tickets := &pb.CommittedTicketsRequest{[][]byte{
		tix, err := convertTicketHashes(v.VoteDetails.EligibleTickets)
		if err != nil {
			fmt.Printf("Ticket pool corrupt: %v %v\n",
				v.Vote.Token, err)
			continue
		}
		ctres, err := client.CommittedTickets(ctx,
			&pb.CommittedTicketsRequest{
				Tickets: tix,
			})
		if err != nil {
			fmt.Printf("Ticket pool verification: %v %v\n",
				v.Vote.Token, err)
			continue
		}

		// Bail if there are no eligible tickets
		if len(ctres.Tickets) == 0 {
			fmt.Printf("No eligible tickets: %v\n", v.Vote.Token)
		}

		// Display vote bits
		fmt.Printf("Vote: %v\n", v.Vote.Token)
		fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
		fmt.Printf("  Start block     : %v\n", v.VoteDetails.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", v.VoteDetails.EndHeight)
		fmt.Printf("  Mask            : %v\n", v.Vote.Mask)
		fmt.Printf("  Eligible tickets: %v\n", len(ctres.Tickets))
		for _, vo := range v.Vote.Options {
			fmt.Printf("  Vote Option:\n")
			fmt.Printf("    Id                   : %v\n", vo.Id)
			fmt.Printf("    Description          : %v\n",
				vo.Description)
			fmt.Printf("    Bits                 : %v\n", vo.Bits)
			fmt.Printf("    To choose this option: "+
				"politeiavoter vote %v %v\n", v.Vote.Token,
				vo.Id)
		}
	}

	return nil
}

func (c *ctx) _vote(token, voteId string) (*v1.CastVotesReply, error) {
	cv := v1.CastVotes{
		Votes: []v1.Vote{
			{
				Ticket:    "NOTYET",
				Token:     token,
				Vote:      "",
				Signature: "nosignature",
			},
		},
	}
	responseBody, err := c.makeRequest("POST", v1.RouteCastVotes, &cv)
	if err != nil {
		return nil, err
	}

	var vr v1.CastVotesReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal CastVoteReply: %v",
			err)
	}

	return &vr, nil
}

func (c *ctx) vote(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("vote: not enough arguments")
	}

	cv, err := c._vote(args[0], args[1])
	if err != nil {
		return err
	}
	_ = cv

	return fmt.Errorf("not yet")
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
			case "vote":
				return c.vote(args[1:])
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
