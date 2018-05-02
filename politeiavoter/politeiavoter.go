package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
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
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/crypto/ssh/terminal"
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
	fmt.Fprintf(os.Stderr, "  tally              - Tally votes on a proposal\n")
	//fmt.Fprintf(os.Stderr, "  startvote          - Instruct vote to start "+
	//	"(admin only)\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// ProvidePrivPassphrase is used to prompt for the private passphrase which
// maybe required during upgrades.
func ProvidePrivPassphrase() ([]byte, error) {
	prompt := "Enter the private passphrase of your wallet: "
	for {
		fmt.Print(prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		return pass, nil
	}
}

type ctx struct {
	client *http.Client
	cfg    *config
	id     *identity.PublicIdentity
	csrf   string

	// wallet grpc
	ctx    context.Context
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet pb.WalletServiceClient
}

func newClient(skipVerify bool, cfg *config) (*ctx, error) {
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

	// Wallet GRPC
	creds, err := credentials.NewClientTLSFromFile(cfg.WalletCert, "")
	if err != nil {
		return nil, err
	}
	conn, err := grpc.Dial("127.0.0.1:19111", grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	wallet := pb.NewWalletServiceClient(conn)

	// return context
	return &ctx{
		ctx:    context.Background(),
		creds:  creds,
		conn:   conn,
		wallet: wallet,
		cfg:    cfg,
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

	fullRoute := c.cfg.PoliteiaWWW + v1.PoliteiaWWWAPIRoute + v1.RouteVersion
	log.Debugf("Request: GET %v", fullRoute)

	log.Tracef("%v  ", string(requestBody))

	log.Debugf("Request: %v", fullRoute)
	req, err := http.NewRequest(http.MethodGet, fullRoute,
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
	c, err := newClient(true, cfg)
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
	log.Debugf("Request: %v %v", method, fullRoute)
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

	// Get latest block
	ar, err := c.wallet.Accounts(c.ctx, &pb.AccountsRequest{})
	if err != nil {
		return err
	}
	latestBlock := ar.CurrentBlockHeight
	//fmt.Printf("Current block: %v\n", latestBlock)

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
			log.Errorf("invalid vote bits: %v",
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
		tix, err := convertTicketHashes(v.VoteDetails.EligibleTickets)
		if err != nil {
			fmt.Printf("Ticket pool corrupt: %v %v\n",
				v.Vote.Token, err)
			continue
		}
		ctres, err := c.wallet.CommittedTickets(c.ctx,
			&pb.CommittedTicketsRequest{
				Tickets: tix,
			})
		if err != nil {
			fmt.Printf("Ticket pool verification: %v %v\n",
				v.Vote.Token, err)
			continue
		}

		// Bail if there are no eligible tickets
		if len(ctres.TicketAddresses) == 0 {
			fmt.Printf("No eligible tickets: %v\n", v.Vote.Token)
		}

		// Display vote bits
		fmt.Printf("Vote: %v\n", v.Vote.Token)
		fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
		fmt.Printf("  Start block     : %v\n", v.VoteDetails.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", v.VoteDetails.EndHeight)
		fmt.Printf("  Mask            : %v\n", v.Vote.Mask)
		fmt.Printf("  Eligible tickets: %v\n", len(ctres.TicketAddresses))
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

func (c *ctx) _vote(token, voteId string) ([]string, *v1.BallotReply, error) {
	// XXX This is expensive but we need the snapshot of the votes. Later
	// replace this with a locally saved file in order to prevent sending
	// the same questions mutliple times.
	i, err := c._inventory()
	if err != nil {
		return nil, nil, err
	}

	// Find proposal
	var (
		prop    *v1.ProposalVoteTuple
		voteBit string
	)
	for _, v := range i.Votes {
		if v.Proposal.CensorshipRecord.Token != token {
			continue
		}

		// Validate voteId
		found := false
		for _, vv := range v.Vote.Options {
			if vv.Id == voteId {
				found = true
				voteBit = strconv.FormatUint(vv.Bits, 16)
				break
			}

		}
		if !found {
			return nil, nil, fmt.Errorf("vote id not found: %v",
				voteId)
		}

		// We found the propr and we have a proper vote id.
		prop = &v
		break
	}
	if prop == nil {
		return nil, nil, fmt.Errorf("proposal not found: %v", token)
	}

	// Find eligble tickets
	tix, err := convertTicketHashes(prop.VoteDetails.EligibleTickets)
	if err != nil {
		return nil, nil, fmt.Errorf("ticket pool corrupt: %v %v",
			token, err)
	}
	ctres, err := c.wallet.CommittedTickets(c.ctx,
		&pb.CommittedTicketsRequest{
			Tickets: tix,
		})
	if err != nil {
		return nil, nil, fmt.Errorf("ticket pool verification: %v %v",
			token, err)
	}
	if len(ctres.TicketAddresses) == 0 {
		return nil, nil, fmt.Errorf("no eligible tickets found")
	}

	passphrase, err := ProvidePrivPassphrase()
	if err != nil {
		return nil, nil, err
	}

	// Sign all tickets
	sm := &pb.SignMessagesRequest{
		Passphrase: passphrase,
		Messages: make([]*pb.SignMessagesRequest_Message, 0,
			len(ctres.TicketAddresses)),
	}
	for _, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return nil, nil, err
		}
		msg := token + h.String() + voteBit
		sm.Messages = append(sm.Messages, &pb.SignMessagesRequest_Message{
			Address: v.Address,
			Message: msg,
		})
	}
	smr, err := c.wallet.SignMessages(c.ctx, sm)
	if err != nil {
		return nil, nil, err
	}

	// Make sure all signatures worked
	for k, v := range smr.Replies {
		if v.Error == "" {
			continue
		}
		return nil, nil, fmt.Errorf("signature failed index %v: %v",
			k, v.Error)
	}

	// Note that ctres, sm and smr use the same index.
	cv := v1.Ballot{
		Votes: make([]v1.CastVote, 0, len(ctres.TicketAddresses)),
	}
	tickets := make([]string, 0, len(ctres.TicketAddresses))
	for k, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return nil, nil, err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)
		cv.Votes = append(cv.Votes, v1.CastVote{
			Token:     token,
			Ticket:    h.String(),
			VoteBit:   voteBit,
			Signature: signature,
		})
		tickets = append(tickets, h.String())
	}

	// Vote on the supplied proposal
	responseBody, err := c.makeRequest("POST", v1.RouteCastVotes, &cv)
	if err != nil {
		return nil, nil, err
	}

	var vr v1.BallotReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not unmarshal CastVoteReply: %v",
			err)
	}

	return tickets, &vr, nil
}

func (c *ctx) vote(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("vote: not enough arguments %v", args)
	}

	tickets, cv, err := c._vote(args[0], args[1])
	if err != nil {
		return err
	}

	// Verify vote replies
	failedReceipts := make([]v1.CastVoteReply, 0,
		len(cv.Receipts))
	for _, v := range cv.Receipts {
		if v.Error != "" {
			failedReceipts = append(failedReceipts, v)
			continue
		}
		sig, err := identity.SignatureFromString(v.Signature)
		if err != nil {
			v.Error = err.Error()
			failedReceipts = append(failedReceipts, v)
			continue
		}
		if !c.id.VerifyMessage([]byte(v.ClientSignature), *sig) {
			v.Error = "Could not verify receipt " + v.ClientSignature
			failedReceipts = append(failedReceipts, v)
		}

	}
	fmt.Printf("Votes succeeded: %v\n", len(cv.Receipts)-
		len(failedReceipts))
	fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
	for k, v := range failedReceipts {
		fmt.Printf("Failed vote    : %v %v\n", tickets[k], v.Error)
	}

	return nil
}

func (c *ctx) _tally(token string) (*v1.VoteResultsReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteVoteResults,
		v1.VoteResults{
			Token: token,
		})
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

func (c *ctx) tally(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("tally: not enough arguments %v", args)
	}

	t, err := c._tally(args[0])
	if err != nil {
		return err
	}

	// tally votes
	count := make(map[uint64]uint)
	var total uint
	for _, v := range t.CastVotes {
		bits, err := strconv.ParseUint(v.VoteBit, 10, 64)
		if err != nil {
			return err
		}
		count[bits]++
		total++
	}

	if total == 0 {
		return fmt.Errorf("no votes recorded")
	}

	// Dump
	for _, vo := range t.Vote.Options {
		fmt.Printf("Vote Option:\n")
		fmt.Printf("  Id                   : %v\n", vo.Id)
		fmt.Printf("  Description          : %v\n",
			vo.Description)
		fmt.Printf("  Bits                 : %v\n", vo.Bits)
		c := count[vo.Bits]
		fmt.Printf("  Votes received       : %v\n", c)
		if total == 0 {
			continue
		}
		fmt.Printf("  Percentage           : %v%%\n",
			(float64(c))/float64(total)*100)
	}

	return nil
}

func (c *ctx) login(email, password string) (*v1.LoginReply, error) {
	l := v1.Login{
		Email:    email,
		Password: password,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteLogin, l)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v",
			err)
	}

	return &lr, nil
}

func (c *ctx) _startVote(sv *v1.StartVote) (*v1.StartVoteReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteStartVote, sv)
	if err != nil {
		return nil, err
	}

	var svr v1.StartVoteReply
	err = json.Unmarshal(responseBody, &svr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal StartVoteReply: %v",
			err)
	}

	return &svr, nil
}

func (c *ctx) startVote(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("startvote: not enough arguments, expected:" +
			"identityfile email password token")
	}

	// startvote identityfile email password token
	fi, err := identity.LoadFullIdentity(args[0])
	if err != nil {
		return err
	}

	// Login as admin
	lr, err := c.login(args[1], args[2])
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return fmt.Errorf("user is not an admin")
	}

	sv := v1.StartVote{
		PublicKey: hex.EncodeToString(c.id.Key[:]),
		Vote: v1.Vote{
			Token:    args[3],
			Mask:     0x03, // bit 0 no, bit 1 yes
			Duration: 2016, // 1 week
			Options: []v1.VoteOption{
				{
					Id:          "no",
					Description: "Don't approve proposal",
					Bits:        0x01,
				},
				{
					Id:          "yes",
					Description: "Approve proposal",
					Bits:        0x02,
				},
			},
		},
	}
	sig := fi.SignMessage([]byte(args[1]))
	sv.Signature = hex.EncodeToString(sig[:])

	svr, err := c._startVote(&sv)
	if err != nil {
		return err
	}
	_ = svr

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
	// Close GRPC
	defer c.conn.Close()

	// Scan through command line arguments.
	for i, a := range args {
		// Select action
		if i == 0 {
			switch a {
			case "inventory":
				return c.inventory()
			case "vote":
				return c.vote(args[1:])
			case "startvote":
				// This remains undocumented because it is for
				// testing only.
				return c.startVote(args[1:])
			case "tally":
				return c.tally(args[1:])
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
