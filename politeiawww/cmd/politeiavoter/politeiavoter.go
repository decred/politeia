// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"container/list"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	failedJournal  = "failed.json"
	successJournal = "success.json"
	workJournal    = "work.json"
)

func generateSeed() (int64, error) {
	var seedBytes [8]byte
	_, err := crand.Read(seedBytes[:])
	if err != nil {
		return 0, err
	}
	return new(big.Int).SetBytes(seedBytes[:]).Int64(), nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiavoter [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  inventory - Retrieve all proposals"+
		" that are being voted on\n")
	fmt.Fprintf(os.Stderr, "  vote      - Vote on a proposal\n")
	fmt.Fprintf(os.Stderr, "  tally     - Tally votes on a proposal\n")
	fmt.Fprintf(os.Stderr, "  verify    - Verify votes on a proposal\n")
	//fmt.Fprintf(os.Stderr, "  startvote          - Instruct vote to start "+
	//	"(admin only)\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// walletPassphrase returns the wallet passphrase from the config if one was
// provided or prompts the user for their wallet passphrase if one was not
// provided.
func (c *ctx) walletPassphrase() ([]byte, error) {
	if c.cfg.WalletPassphrase != "" {
		return []byte(c.cfg.WalletPassphrase), nil
	}

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

// verifyMessage verifies a message is properly signed.
// Copied from https://github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func verifyMessage(params *chaincfg.Params, address, message, signature string) (bool, error) {
	// Decode the provided address.
	addr, err := dcrutil.DecodeAddress(address, params)
	if err != nil {
		return false, fmt.Errorf("Could not decode address: %v",
			err)
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*dcrutil.AddressPubKeyHash); !ok {
		return false, fmt.Errorf("Address is not a pay-to-pubkey-hash "+
			"address: %v", address)
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("Malformed base64 encoding: %v", err)
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, message)
	expectedMessageHash := chainhash.HashB(buf.Bytes())
	pk, wasCompressed, err := ecdsa.RecoverCompact(sig,
		expectedMessageHash)
	if err != nil {
		// Mirror Bitcoin Core behavior, which treats error in
		// RecoverCompact as invalid signature.
		return false, nil
	}

	// Reconstruct the pubkey hash.
	dcrPK := pk
	var serializedPK []byte
	if wasCompressed {
		serializedPK = dcrPK.SerializeCompressed()
	} else {
		serializedPK = dcrPK.SerializeUncompressed()
	}
	a, err := dcrutil.NewAddressSecpPubKey(serializedPK, activeNetParams.Params)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return a.Address() == address, nil
}

// BallotResult is a tupple of the ticket and receipt. We combine the too
// because CastVoteReply does not contain the ticket address.
type BallotResult struct {
	Ticket  string           `json:"ticket"`  // ticket address
	Receipt v1.CastVoteReply `json:"receipt"` // result of vote
}

// ctx is the client context.
type ctx struct {
	sync.RWMutex                      // retryQ lock
	retryQ             *list.List     // retry message queue FIFO
	retryWG            sync.WaitGroup // Wait for retry loop to exit
	mainLoopDone       chan struct{}  // message when done
	mainLoopForceExit  chan struct{}  // message when main loop forces an exit
	retryLoopForceExit chan struct{}  // message when retry loop forces an exit
	ballotResults      []BallotResult // results of voting
	voteIntervalQ      *list.List     // work that has to be completed

	run time.Time // when this run started

	cfg *config // application config

	// https
	client    *http.Client
	id        *identity.PublicIdentity
	userAgent string

	// wallet grpc
	wctx   context.Context
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet pb.WalletServiceClient
}

// voteInterval is an internal structure that is used to precalculate all
// timing intervals and vote details. This is a JSON structure for logging
// purposes.
type voteInterval struct {
	Vote v1.CastVote   `json:"vote"` // RPC vote
	At   time.Duration `json:"at"`   // Delay to fire off vote
}

func newClient(shutdownCtx context.Context, cfg *config) (*ctx, error) {
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

	// Wallet GRPC
	serverCAs := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile(cfg.WalletCert)
	if err != nil {
		return nil, err
	}
	if !serverCAs.AppendCertsFromPEM(serverCert) {
		return nil, fmt.Errorf("no certificates found in %s",
			cfg.WalletCert)
	}
	keypair, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("read client keypair: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keypair},
		RootCAs:      serverCAs,
	})

	conn, err := grpc.Dial(cfg.WalletHost,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	wallet := pb.NewWalletServiceClient(conn)

	// return context
	return &ctx{
		run:                time.Now(),
		retryQ:             new(list.List),
		voteIntervalQ:      new(list.List),
		mainLoopDone:       make(chan struct{}),
		mainLoopForceExit:  make(chan struct{}),
		retryLoopForceExit: make(chan struct{}),
		wctx:               shutdownCtx,
		creds:              creds,
		conn:               conn,
		wallet:             wallet,
		cfg:                cfg,
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		},
		userAgent: fmt.Sprintf("politeiavoter/%s", cfg.Version),
	}, nil
}

type JSONTime struct {
	Time string `json:"time"`
}

func (c *ctx) jsonLog(filename, token string, work ...interface{}) error {
	dir := filepath.Join(c.cfg.voteDir, token)
	os.MkdirAll(dir, 0700)

	f := filepath.Join(dir, fmt.Sprintf("%v.%v", filename, c.run.Unix()))
	fh, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer fh.Close()

	e := json.NewEncoder(fh)
	e.SetIndent("", "  ")
	err = e.Encode(JSONTime{
		Time: time.Now().Format(time.StampNano),
	})
	if err != nil {
		return err
	}
	for _, v := range work {
		err = e.Encode(v)
		if err != nil {
			return err
		}
	}

	return nil
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

	req, err := http.NewRequestWithContext(c.wctx, method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, ErrRetry{
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

		return nil, ErrRetry{
			At:   "r.StatusCode != http.StatusOK",
			Err:  err,
			Body: responseBody,
			Code: r.StatusCode,
		}
	}

	return responseBody, nil
}

func (c *ctx) makeRequestFail(method, route string, b interface{}) ([]byte, error) {
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

	req, err := http.NewRequestWithContext(c.wctx, method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, ErrRetry{
			At:  "c.client.Do(req)",
			Err: err,
		}
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	log.Tracef("Response: %v %v", r.StatusCode, string(responseBody))

	r.StatusCode = http.StatusInternalServerError
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil && ue.ErrorCode != 0 {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode],
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, ErrRetry{
			At:   "r.StatusCode != http.StatusOK",
			Err:  err,
			Body: responseBody,
			Code: r.StatusCode,
		}
	}

	return responseBody, nil
}

// getVersion retursn the server side version structure.
func (c *ctx) getVersion() (*v1.VersionReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, v1.RouteVersion, nil)
	if err != nil {
		return nil, err
	}

	var v v1.VersionReply
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	return &v, nil
}

// firstContact connect to the wallet and it obtains the version structure from
// the politeia server.
func firstContact(shutdownCtx context.Context, cfg *config) (*ctx, error) {
	// Always hit / first for to obtain the server identity and api version
	c, err := newClient(shutdownCtx, cfg)
	if err != nil {
		return nil, err
	}
	version, err := c.getVersion()
	if err != nil {
		return nil, err
	}
	log.Debugf("Version: %v", version.Version)
	log.Debugf("Route  : %v", version.Route)
	log.Debugf("Pubkey : %v", version.PubKey)

	c.id, err = util.IdentityFromString(version.PubKey)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// eligibleVotes takes a vote result reply that contains the full list of
// eligible tickets as well as the votes already cast along with a committed
// tickets response from wallet which consists of a list of tickets the wallet
// is aware of and returns a list of tickets that the wallet is actually able
// to sign and vote with.
//
// When a ticket has already voted, the signature is also checked to ensure it
// is valid.  In the case it is invalid, and the wallet can sign it, the ticket
// is included so it may be resubmitted.  This could be caused by bad data on
// the server or if the server is lying to the client.
func (c *ctx) eligibleVotes(vrr *v1.VoteResultsReply, ctres *pb.CommittedTicketsResponse) ([]*pb.CommittedTicketsResponse_TicketAddress, error) {
	// Put cast votes into a map to filter in linear time
	castVotes := make(map[string]v1.CastVote)
	for _, v := range vrr.CastVotes {
		castVotes[v.Ticket] = v
	}

	// Filter out tickets that have already voted. If a ticket has
	// voted but the signature is invalid, resubmit the vote. This
	// could be caused by bad data on the server or if the server is
	// lying to the client.
	eligible := make([]*pb.CommittedTicketsResponse_TicketAddress, 0,
		len(ctres.TicketAddresses))
	for _, t := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(t.Ticket)
		if err != nil {
			return nil, err
		}

		// Filter out tickets tracked by imported xpub accounts.
		r, err := c.wallet.GetTransaction(context.TODO(), &pb.GetTransactionRequest{
			TransactionHash: h[:],
		})
		if err != nil {
			log.Error(err)
			continue
		}
		tx := new(wire.MsgTx)
		err = tx.Deserialize(bytes.NewReader(r.Transaction.Transaction))
		if err != nil {
			log.Error(err)
			continue
		}
		addr, err := stake.AddrFromSStxPkScrCommitment(tx.TxOut[1].PkScript, activeNetParams.Params)
		if err != nil {
			log.Error(err)
			continue
		}
		vr, err := c.wallet.ValidateAddress(context.TODO(), &pb.ValidateAddressRequest{
			Address: addr.String(),
		})
		if err != nil {
			log.Error(err)
			continue
		}
		if vr.AccountNumber >= 1<<31-1 { // imported xpub account
			// do not append to filtered.
			continue
		}

		var params *chaincfg.Params
		if c.cfg.TestNet {
			params = chaincfg.TestNet3Params()
		} else {
			params = chaincfg.MainNetParams()
		}

		v, ok := castVotes[h.String()]
		if !ok || !verifyV1Vote(params, t.Address, &v) {
			eligible = append(eligible, t)
		}
	}

	return eligible, nil
}

func (c *ctx) _inventory() (*v1.ActiveVoteReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, v1.RouteActiveVote, nil)
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
	ar, err := c.wallet.Accounts(c.wctx, &pb.AccountsRequest{})
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
		if v.StartVote.Vote.Token == "" || v.StartVote.Vote.Mask == 0 ||
			v.StartVote.Vote.Options == nil {
			// This should not happen
			log.Errorf("invalid vote bits: %v",
				v.Proposal.CensorshipRecord.Token)
			continue
		}

		// Sanity, check if vote has expired
		endHeight, err := strconv.ParseInt(v.StartVoteReply.EndHeight, 10, 32)
		if err != nil {
			return err
		}
		if int64(latestBlock) > endHeight {
			// Should not happen
			fmt.Printf("Vote expired: current %v > end %v %v\n",
				endHeight, latestBlock, v.StartVote.Vote.Token)
			continue
		}

		// Ensure eligibility
		tix, err := convertTicketHashes(v.StartVoteReply.EligibleTickets)
		if err != nil {
			fmt.Printf("Ticket pool corrupt: %v %v\n",
				v.StartVote.Vote.Token, err)
			continue
		}
		ctres, err := c.wallet.CommittedTickets(c.wctx,
			&pb.CommittedTicketsRequest{
				Tickets: tix,
			})
		if err != nil {
			fmt.Printf("Ticket pool verification: %v %v\n",
				v.StartVote.Vote.Token, err)
			continue
		}

		// Bail if there are no eligible tickets
		if len(ctres.TicketAddresses) == 0 {
			fmt.Printf("No eligible tickets: %v\n", v.StartVote.Vote.Token)
		}

		// _tally provides the eligible tickets snapshot as well as a list of
		// the votes that have already been cast. Use these to filter out the
		// tickets that have already voted.
		vrr, err := c._tally(v.StartVote.Vote.Token)
		if err != nil {
			fmt.Printf("Failed to obtain voting results for %v: %v\n",
				v.StartVote.Vote.Token, err)
			continue
		}

		// Filter out tickets that have already voted or are otherwise
		// ineligible for the wallet to sign.  Note that tickets that have
		// already voted, but have an invalid signature are included so they
		// may be resubmitted.
		eligible, err := c.eligibleVotes(vrr, ctres)
		if err != nil {
			fmt.Printf("Eligible vote filtering error: %v %v\n",
				v.StartVote.Vote.Token, err)
			continue
		}

		// Display vote bits
		fmt.Printf("Vote: %v\n", v.StartVote.Vote.Token)
		fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
		fmt.Printf("  Start block     : %v\n", v.StartVoteReply.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", v.StartVoteReply.EndHeight)
		fmt.Printf("  Mask            : %v\n", v.StartVote.Vote.Mask)
		fmt.Printf("  Eligible tickets: %v\n", len(ctres.TicketAddresses))
		fmt.Printf("  Eligible votes  : %v\n", len(eligible))
		for _, vo := range v.StartVote.Vote.Options {
			fmt.Printf("  Vote Option:\n")
			fmt.Printf("    Id                   : %v\n", vo.Id)
			fmt.Printf("    Description          : %v\n",
				vo.Description)
			fmt.Printf("    Bits                 : %v\n", vo.Bits)
			fmt.Printf("    To choose this option: "+
				"politeiavoter vote %v %v\n", v.StartVote.Vote.Token,
				vo.Id)
		}
	}

	return nil
}

type ErrRetry struct {
	At   string      `json:"at"`   // where in the code
	Body []byte      `json:"body"` // http body if we have one
	Code int         `json:"code"` // http code
	Err  interface{} `json:"err"`  // underlying error
}

func (e ErrRetry) Error() string {
	return fmt.Sprintf("retry error: %v (%v) %v", e.Code, e.At, e.Err)
}

// sendVoteFail isa test function that will fail a Ballot call with a retryable
// error.
func (c *ctx) sendVoteFail(ballot *v1.Ballot) (*v1.CastVoteReply, error) {
	return nil, ErrRetry{
		At: "sendVoteFail",
	}
}

func (c *ctx) sendVote(ballot *v1.Ballot) (*v1.CastVoteReply, error) {
	if len(ballot.Votes) != 1 {
		return nil, fmt.Errorf("sendVote: only one vote allowed")
	}

	responseBody, err := c.makeRequest(http.MethodPost, v1.RouteCastVotes, ballot)
	if err != nil {
		return nil, err
	}

	var vr v1.BallotReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"CastVoteReply: %v", err)
	}
	if len(vr.Receipts) != 1 {
		// Should be impossible
		return nil, fmt.Errorf("sendVote: received multiple answers")
	}

	return &vr.Receipts[0], nil
}

// dumpComplete dumps the completed votes in this run.
func (c *ctx) dumpComplete() {
	c.RLock()
	defer c.RUnlock()

	fmt.Printf("Completed votes (%v):\n", len(c.ballotResults))
	for _, v := range c.ballotResults {
		fmt.Printf("  %v %v\n", v.Ticket, v.Receipt.Error)
	}
}

// dumpTogo dumps the votes that have not been casrt yet.
func (c *ctx) dumpTogo() {
	c.RLock()
	defer c.RUnlock()

	fmt.Printf("Votes queued (%v):\n", c.voteIntervalQ.Len())
	for e := c.voteIntervalQ.Front(); e != nil; e = e.Next() {
		r := e.Value.(*voteInterval)
		fmt.Printf("  %v %v\n", r.Vote.Ticket, r.At)
	}
}

func (c *ctx) voteIntervalPush(v *voteInterval) {
	c.Lock()
	defer c.Unlock()
	c.voteIntervalQ.PushBack(v)
}

func (c *ctx) voteIntervalPop() *voteInterval {
	c.Lock()
	defer c.Unlock()

	e := c.voteIntervalQ.Front()
	if e == nil {
		return nil
	}
	return c.voteIntervalQ.Remove(e).(*voteInterval)
}

func (c *ctx) voteIntervalLen() uint64 {
	c.RLock()
	defer c.RUnlock()
	return uint64(c.voteIntervalQ.Len())
}

// _voteTrickler trickles votes to the server. The idea here is to not issue
// large number of votes in one go to the server at the same time giving away
// which IP address owns what votes.
func (c *ctx) _voteTrickler(token string) error {
	// Synthesize reply, needs locking once go routines launch
	voteCount := c.voteIntervalLen()
	c.ballotResults = make([]BallotResult, 0, voteCount)

	// Launch retry loop
	c.retryWG.Add(1)
	go c.retryLoop()

	for i := 0; ; {
		vote := c.voteIntervalPop()
		if vote == nil {
			break
		}
		log.Tracef("mainLoop pop %v", spew.Sdump(vote))

		// Fire off the first vote without a delay
		if i == 0 {
			goto vote
		}

		fmt.Printf("Next vote at %v (delay %v)\n",
			time.Now().Add(vote.At).Format(time.Stamp), vote.At)

		select {
		case <-c.wctx.Done():
			goto exit
		case <-time.After(vote.At):
		case <-c.retryLoopForceExit:
			// The retry loop is forcing an exit. Put vote back
			// into the queue before exiting so the vote summary
			// statistics are correct.
			c.voteIntervalPush(vote)
			fmt.Printf("Forced exit main vote queue.\n")
			goto exit
		}

	vote:
		fmt.Printf("Voting: %v/%v %v\n", i+1, voteCount,
			vote.Vote.Ticket)

		// Send off vote
		b := v1.Ballot{Votes: []v1.CastVote{vote.Vote}}
		br, err := c.sendVote(&b)
		var e ErrRetry
		if errors.As(err, &e) {
			// Append failed vote to retry queue
			fmt.Printf("Vote rescheduled: %v\n", vote.Vote.Ticket)
			err := c.jsonLog(failedJournal, token, b, e)
			if err != nil {
				return err
			}
			c.retryPush(&retry{vote: vote.Vote})
		} else if err != nil {
			// Unrecoverable error
			return fmt.Errorf("unrecoverable error: %v",
				err)
		} else {
			// Vote completed
			result := BallotResult{
				Ticket:  vote.Vote.Ticket,
				Receipt: *br,
			}
			c.Lock()
			c.ballotResults = append(c.ballotResults, result)
			c.Unlock()

			if br.ErrorStatus == decredplugin.ErrorStatusVoteHasEnded {
				// Force an exit of the both the main queue and the
				// retry queue if the voting period has ended.
				err = c.jsonLog(failedJournal, token, br)
				if err != nil {
					return err
				}
				fmt.Printf("Vote has ended; forced exit main vote queue.\n")
				fmt.Printf("Awaiting retry vote queue to exit.\n")
				c.mainLoopForceExit <- struct{}{}
				goto exit
			}

			err = c.jsonLog(successJournal, token, result)
			if err != nil {
				return err
			}
		}

		// Go to next vote
		i++
	}

	// Tell retry loop that main loop is done
	log.Debugf("_voteTrickler: main loop done")
	fmt.Printf("Awaiting retry vote queue to complete.\n")
	c.mainLoopDone <- struct{}{}

	// Wait for retry loop to exit
	c.retryWG.Wait()
	log.Debugf("ballotResults %v", spew.Sdump(c.ballotResults))

exit:
	return nil
}

// verifyV1Vote verifies the signature of the passed in v1 vote. If the
// signature is invalid or if an error occurs during validation, the error will
// be logged instead of being returned. This is to prevent interuptions to
// politeavoter while it is in the process of casting votes.
func verifyV1Vote(params *chaincfg.Params, address string, vote *v1.CastVote) bool {
	sig, err := hex.DecodeString(vote.Signature)
	if err != nil {
		log.Errorf("Could not decode signature %v: %v",
			vote.Ticket, err)
		return false
	}

	msg := vote.Token + vote.Ticket + vote.VoteBit

	validated, err := verifyMessage(params, address, msg,
		base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		log.Errorf("Could not verify signature %v: %v",
			vote.Ticket, err)
		return false
	}
	if !validated {
		log.Errorf("Invalid signature %v: %v",
			vote.Ticket, vote.Signature)
		return false
	}

	return true
}

func (c *ctx) _vote(token, voteId string) error {
	seed, err := generateSeed()
	if err != nil {
		return err
	}

	// Verify vote is still active
	vsr, err := c._summary(token)
	if err != nil {
		return err
	}
	vs, ok := vsr.Summaries[token]
	if !ok {
		return fmt.Errorf("proposal does not exist: %v", token)
	}
	if vs.Status != v1.PropVoteStatusStarted {
		return fmt.Errorf("proposal vote is not active: %v", vs.Status)
	}
	bestBlock := vsr.BestBlock

	// _tally provides the eligible tickets snapshot as well as a list of
	// the votes that have already been cast. We use these to filter out
	// the tickets that have already voted.
	vrr, err := c._tally(token)
	if err != nil {
		return err
	}

	// Validate voteId
	var (
		voteBit string
		found   bool
	)
	for _, vv := range vrr.StartVote.Vote.Options {
		if vv.Id == voteId {
			found = true
			voteBit = strconv.FormatUint(vv.Bits, 16)
			break
		}
	}
	if !found {
		return fmt.Errorf("vote id not found: %v", voteId)
	}

	// Find eligble tickets
	tix, err := convertTicketHashes(vrr.StartVoteReply.EligibleTickets)
	if err != nil {
		return fmt.Errorf("ticket pool corrupt: %v %v",
			token, err)
	}
	ctres, err := c.wallet.CommittedTickets(c.wctx,
		&pb.CommittedTicketsRequest{
			Tickets: tix,
		})
	if err != nil {
		return fmt.Errorf("ticket pool verification: %v %v",
			token, err)
	}
	if len(ctres.TicketAddresses) == 0 {
		return fmt.Errorf("no eligible tickets found")
	}

	// Filter out tickets that have already voted or are otherwise ineligible
	// for the wallet to sign.  Note that tickets that have already voted, but
	// have an invalid signature are included so they may be resubmitted.
	eligible, err := c.eligibleVotes(vrr, ctres)
	if err != nil {
		return err
	}

	eligibleLen := len(eligible)
	if eligibleLen == 0 {
		return fmt.Errorf("no eligible tickets found")
	}
	r := rand.New(rand.NewSource(seed))
	// Fisher-Yates shuffle the ticket addresses.
	for i := 0; i < eligibleLen; i++ {
		// Pick a number between current index and the end.
		j := r.Intn(eligibleLen-i) + i
		eligible[i], eligible[j] = eligible[j], eligible[i]
	}
	ctres.TicketAddresses = eligible

	passphrase, err := c.walletPassphrase()
	if err != nil {
		return err
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
			return err
		}
		msg := token + h.String() + voteBit
		sm.Messages = append(sm.Messages, &pb.SignMessagesRequest_Message{
			Address: v.Address,
			Message: msg,
		})
	}
	smr, err := c.wallet.SignMessages(c.wctx, sm)
	if err != nil {
		return err
	}

	// Make sure all signatures worked
	for k, v := range smr.Replies {
		if v.Error == "" {
			continue
		}
		return fmt.Errorf("signature failed index %v: %v", k, v.Error)
	}

	if c.cfg.Trickle {
		go c.statsHandler()

		// Calculate vote duration if not set
		if c.cfg.voteDuration.Seconds() == 0 {
			blocksLeft := vs.EndHeight - bestBlock
			if blocksLeft < c.cfg.blocksPerHour {
				return fmt.Errorf("less than one hour left to" +
					" vote, please set --voteduration " +
					"manually")
			}
			c.cfg.voteDuration = activeNetParams.TargetTimePerBlock *
				(time.Duration(blocksLeft) -
					time.Duration(c.cfg.blocksPerHour))
		}

		// Generate work
		err := c.calculateTrickle(token, voteBit, ctres, smr)
		if err != nil {
			return err
		}

		return c._voteTrickler(token)
	}

	// Vote everything at once.

	// Note that ctres, sm and smr use the same index.
	cv := v1.Ballot{
		Votes: make([]v1.CastVote, 0, len(ctres.TicketAddresses)),
	}
	c.ballotResults = make([]BallotResult, 0, len(ctres.TicketAddresses))
	for k, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)
		cv.Votes = append(cv.Votes, v1.CastVote{
			Token:     token,
			Ticket:    h.String(),
			VoteBit:   voteBit,
			Signature: signature,
		})

		// Prep results since we don't CastVoteReply doesn't return
		// ticket address.
		c.ballotResults = append(c.ballotResults, BallotResult{
			Ticket: h.String(),
		})
	}

	// Vote on the supplied proposal
	responseBody, err := c.makeRequest(http.MethodPost, v1.RouteCastVotes, &cv)
	if err != nil {
		return err
	}

	var vr v1.BallotReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal CastVoteReply: %v",
			err)
	}

	// Finnish ballotResults
	if len(vr.Receipts) != len(c.ballotResults) {
		return fmt.Errorf("unexpected receipt count got %v wanted %v",
			len(vr.Receipts), len(c.ballotResults))
	}
	for k := range vr.Receipts {
		c.ballotResults[k].Receipt = vr.Receipts[k]
	}

	return nil
}

func (c *ctx) vote(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("vote: not enough arguments %v", args)
	}

	err := c._vote(args[0], args[1])
	if err != nil {
		return err
	}

	// Verify vote replies
	failedReceipts := make([]BallotResult, 0,
		len(c.ballotResults))
	for _, v := range c.ballotResults {
		if v.Receipt.Error != "" {
			failedReceipts = append(failedReceipts, v)
			continue
		}
		sig, err := identity.SignatureFromString(v.Receipt.Signature)
		if err != nil {
			v.Receipt.Error = err.Error()
			failedReceipts = append(failedReceipts, v)
			continue
		}
		if !c.id.VerifyMessage([]byte(v.Receipt.ClientSignature), *sig) {
			v.Receipt.Error = "Could not verify receipt " +
				v.Receipt.ClientSignature
			failedReceipts = append(failedReceipts, v)
		}
	}
	fmt.Printf("Votes succeeded: %v\n", len(c.ballotResults)-
		len(failedReceipts))
	fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
	notCast := c.voteIntervalLen() + uint64(c.retryLen())
	if notCast > 0 {
		fmt.Printf("Votes not cast : %v\n", notCast)
	}
	for _, v := range failedReceipts {
		fmt.Printf("Failed vote    : %v %v\n",
			v.Ticket, v.Receipt.Error)
	}

	return nil
}

func (c *ctx) _summary(token string) (*v1.BatchVoteSummaryReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, v1.RouteBatchVoteSummary,
		v1.BatchVoteSummary{Tokens: []string{token}})
	if err != nil {
		return nil, err
	}

	var bvsr v1.BatchVoteSummaryReply
	err = json.Unmarshal(responseBody, &bvsr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"BatchVoteSummary: %v", err)
	}

	return &bvsr, nil
}

func (c *ctx) _tally(token string) (*v1.VoteResultsReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, "/proposals/"+token+"/votes", nil)
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
	for _, vo := range t.StartVote.Vote.Options {
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

type failedTuple struct {
	Time  JSONTime
	Votes v1.Ballot `json:"votes"`
	Error ErrRetry
}

func decodeFailed(filename string, failed map[string][]failedTuple) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)

	var (
		ft     *failedTuple
		ticket string
	)
	state := 0
	for {
		switch state {
		case 0:
			ft = &failedTuple{}
			err = d.Decode(&ft.Time)
			if err != nil {
				// Only expect EOF in state 0
				if err == io.EOF {
					goto exit
				}
				return fmt.Errorf("decode time (%v): %v",
					d.InputOffset(), err)
			}
			state = 1

		case 1:
			err = d.Decode(&ft.Votes)
			if err != nil {
				return fmt.Errorf("decode cast votes (%v): %v",
					d.InputOffset(), err)
			}

			// Save ticket
			if len(ft.Votes.Votes) != 1 {
				// Should not happen
				return fmt.Errorf("decode invalid length %v",
					len(ft.Votes.Votes))
			}
			ticket = ft.Votes.Votes[0].Ticket

			state = 2

		case 2:
			err = d.Decode(&ft.Error)
			if err != nil {
				return fmt.Errorf("decode error retry (%v): %v",
					d.InputOffset(), err)
			}

			// Add to map
			if ticket == "" {
				return fmt.Errorf("decode no ticket found")
			}
			//fmt.Printf("failed ticket %v\n", ticket)
			failed[ticket] = append(failed[ticket], *ft)

			// Reset statemachine
			ft = &failedTuple{}
			ticket = ""
			state = 0
		}
	}

exit:
	return nil
}

type successTuple struct {
	Time   JSONTime
	Result BallotResult
}

func decodeSuccess(filename string, success map[string][]successTuple) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)

	var st *successTuple
	state := 0
	for {
		switch state {
		case 0:
			st = &successTuple{}
			err = d.Decode(&st.Time)
			if err != nil {
				// Only expect EOF in state 0
				if err == io.EOF {
					goto exit
				}
				return fmt.Errorf("decode time (%v): %v",
					d.InputOffset(), err)
			}
			state = 1

		case 1:
			err = d.Decode(&st.Result)
			if err != nil {
				return fmt.Errorf("decode cast votes (%v): %v",
					d.InputOffset(), err)
			}

			// Add to map
			ticket := st.Result.Ticket
			if ticket == "" {
				return fmt.Errorf("decode no ticket found")
			}

			//fmt.Printf("success ticket %v\n", ticket)
			success[ticket] = append(success[ticket], *st)

			// Reset statemachine
			st = &successTuple{}
			state = 0
		}
	}

exit:
	return nil
}

type workTuple struct {
	Time  JSONTime
	Votes []voteInterval
}

func decodeWork(filename string, work map[string][]workTuple) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)

	var (
		wt *workTuple
		t  string
	)
	state := 0
	for {
		switch state {
		case 0:
			wt = &workTuple{}
			err = d.Decode(&wt.Time)
			if err != nil {
				// Only expect EOF in state 0
				if err == io.EOF {
					goto exit
				}
				return fmt.Errorf("decode time (%v): %v",
					d.InputOffset(), err)
			}
			t = wt.Time.Time
			state = 1

		case 1:
			err = d.Decode(&wt.Votes)
			if err != nil {
				return fmt.Errorf("decode votes (%v): %v",
					d.InputOffset(), err)
			}

			// Add to map
			if t == "" {
				return fmt.Errorf("decode no time found")
			}

			work[t] = append(work[t], *wt)

			// Reset statemachine
			wt = &workTuple{}
			t = ""
			state = 0
		}
	}

exit:
	return nil
}

func (c *ctx) verifyVote(vote string) error {
	// Vote directory
	dir := filepath.Join(c.cfg.voteDir, vote)

	// See if vote is ongoing
	vsr, err := c._summary(vote)
	if err != nil {
		return fmt.Errorf("could not obtain proposal status: %v\n",
			err)
	}
	vs, ok := vsr.Summaries[vote]
	if !ok {
		return fmt.Errorf("proposal does not exist: %v", vote)
	}
	if vs.Status != v1.PropVoteStatusFinished {
		return fmt.Errorf("proposal vote not finished: %v\n", vs.Status)
	}

	// Get and cache vote results
	voteResultsFilename := filepath.Join(dir, ".voteresults")
	if !util.FileExists(voteResultsFilename) {
		vrr, err := c._tally(vote)
		if err != nil {
			return fmt.Errorf("failed to obtain voting results "+
				"for %v: %v\n", vote, err)
		}
		f, err := os.Create(voteResultsFilename)
		if err != nil {
			return fmt.Errorf("create cache: %v", err)
		}
		e := json.NewEncoder(f)
		err = e.Encode(vrr)
		if err != nil {
			f.Close()
			_ = os.Remove(voteResultsFilename)
			return fmt.Errorf("encode cache: %v", err)
		}
		f.Close()
	}

	// Open cached results
	f, err := os.Open(voteResultsFilename)
	if err != nil {
		return fmt.Errorf("open cache: %v", err)
	}
	d := json.NewDecoder(f)
	var vrr v1.VoteResultsReply
	err = d.Decode(&vrr)
	if err != nil {
		f.Close()
		return fmt.Errorf("decode cache: %v", err)
	}
	f.Close()

	// Index vote results for more vroom vroom
	eligible := make(map[string]string,
		len(vrr.StartVoteReply.EligibleTickets))
	for _, v := range vrr.StartVoteReply.EligibleTickets {
		eligible[v] = "" // XXX
	}
	cast := make(map[string]string, len(vrr.CastVotes))
	for _, v := range vrr.CastVotes {
		cast[v.Ticket] = "" // XXX
	}

	// Create local work caches
	fa, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	failed := make(map[string][]failedTuple, 128)   // [ticket]result
	success := make(map[string][]successTuple, 128) // [ticket]result
	work := make(map[string][]workTuple, 128)       // [time]work

	fmt.Printf("== Checking vote %v\n", vote)
	for k := range fa {
		name := fa[k].Name()

		filename := filepath.Join(dir, name)
		switch {
		case strings.HasPrefix(name, failedJournal):
			err = decodeFailed(filename, failed)
			if err != nil {
				fmt.Printf("decodeFailed %v: %v\n", filename,
					err)
			}

		case strings.HasPrefix(name, successJournal):
			err = decodeSuccess(filename, success)
			if err != nil {
				fmt.Printf("decodeSuccess %v: %v\n", filename,
					err)
			}

		case strings.HasPrefix(name, workJournal):
			err = decodeWork(filename, work)
			if err != nil {
				fmt.Printf("decodeWork %v: %v\n", filename,
					err)
			}

		case name == ".voteresults":
			// Cache file, skip

		default:
			fmt.Printf("unknown journal: %v\n", name)
		}
	}

	// Count vote statistics
	type voteStat struct {
		ticket  string
		retries int
		failed  int
		success int
	}

	verbose := false
	failedVotes := make(map[string]voteStat)
	tickets := make(map[string]string, 128) // [time]
	for k := range work {
		wts := work[k]

		for kk := range wts {
			wt := wts[kk]

			for kkk := range wt.Votes {
				vi := wt.Votes[kkk]

				if kkk == 0 && verbose {
					fmt.Printf("Vote %v started: %v\n",
						vi.Vote.Token, wt.Time.Time)
				}

				ticket := vi.Vote.Ticket
				tickets[ticket] = "" // XXX
				vs := voteStat{
					ticket: ticket,
				}
				if f, ok := failed[ticket]; ok {
					vs.retries = len(f)
				}
				if s, ok := success[ticket]; ok {
					vs.success = len(s)
					if len(s) != 1 {
						fmt.Printf("multiple success:"+
							" %v %v\n", len(s),
							ticket)
					}
				} else {
					vs.failed = 1
					failedVotes[ticket] = vs
				}

				if verbose {
					fmt.Printf("  ticket: %v retries %v "+
						"success %v failed %v\n",
						vs.ticket, vs.retries,
						vs.success, vs.failed)
				}
			}
		}
	}

	noVote := 0
	failedVote := 0
	completedNotRecorded := 0
	for _, v := range failedVotes {
		reason := "Error"
		if v.retries == 0 {
			if _, ok := cast[v.ticket]; ok {
				completedNotRecorded++
				continue
			}
			reason = "Not attempted"
			noVote++
		}
		if v.failed != 0 {
			fmt.Printf("  FAILED: %v - %v\n", v.ticket, reason)
			failedVote++
			continue
		}
	}
	if noVote != 0 {
		fmt.Printf("  votes that were not attempted: %v\n", noVote)
	}
	if failedVote != 0 {
		fmt.Printf("  votes that failed: %v\n", failedVote)
	}
	if completedNotRecorded != 0 {
		fmt.Printf("  votes that completed but were not recorded: %v\n",
			completedNotRecorded)
	}

	// Cross check results
	eligibleNotFound := 0
	for ticket := range tickets {
		// Did politea see ticket
		if _, ok := eligible[ticket]; !ok {
			fmt.Printf("work ticket not eligble: %v\n", ticket)
			eligibleNotFound++
		}

		// Did politea complete vote
		_, successFound := success[ticket]
		_, failedFound := failedVotes[ticket]
		switch {
		case successFound && failedFound:
			fmt.Printf("  pi vote succeeded and failed, " +
				"impossible condition\n")
		case !successFound && failedFound:
			if _, ok := cast[ticket]; !ok {
				fmt.Printf("  pi vote failed: %v\n", ticket)
			}
		case successFound && !failedFound:
			// Vote succeeded on the first try
		case !successFound && !failedFound:
			fmt.Printf("  pi vote not seen: %v\n", ticket)
		}
	}

	if eligibleNotFound != 0 {
		fmt.Printf("  ineligible tickets: %v\n", eligibleNotFound)
	}

	// Print overall status
	fmt.Printf("  Total votes       : %v\n", len(tickets))
	fmt.Printf("  Successful votes  : %v\n", len(success)+
		completedNotRecorded)
	fmt.Printf("  Unsuccessful votes: %v\n", failedVote)
	if failedVote != 0 {
		fmt.Printf("== Failed votes on proposal %v\n", vote)
	} else {
		fmt.Printf("== NO failed votes on proposal %v\n", vote)
	}

	return nil
}

func (c *ctx) verify(args []string) error {
	// Override 0 to list all possible votes.
	if len(args) == 0 {
		fa, err := ioutil.ReadDir(c.cfg.voteDir)
		if err != nil {
			return err
		}
		fmt.Printf("Votes:\n")
		for k := range fa {
			_, err := hex.DecodeString(fa[k].Name())
			if err != nil {
				continue
			}
			fmt.Printf("  %v\n", fa[k].Name())
		}
	}

	if len(args) == 1 && args[0] == "ALL" {
		fa, err := ioutil.ReadDir(c.cfg.voteDir)
		if err != nil {
			return err
		}
		for k := range fa {
			_, err := hex.DecodeString(fa[k].Name())
			if err != nil {
				continue
			}

			err = c.verifyVote(fa[k].Name())
			if err != nil {
				fmt.Printf("verifyVote: %v\n", err)
			}
		}

		return nil
	}

	for k := range args {
		_, err := hex.DecodeString(args[k])
		if err != nil {
			fmt.Printf("invalid vote: %v\n", args[k])
			continue
		}

		err = c.verifyVote(args[k])
		if err != nil {
			fmt.Printf("verifyVote: %v\n", err)
		}
	}

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
	action := args[0]

	// Get a context that will be canceled when a shutdown signal has been
	// triggered either from an OS signal such as SIGINT (Ctrl+C) or from
	// another subsystem such as the RPC server.
	shutdownCtx := shutdownListener()

	// Contact WWW
	c, err := firstContact(shutdownCtx, cfg)
	if err != nil {
		return err
	}
	// Close GRPC
	defer c.conn.Close()

	// Get block height to validate GRPC creds
	ar, err := c.wallet.Accounts(c.wctx, &pb.AccountsRequest{})
	if err != nil {
		return err
	}
	log.Debugf("Current wallet height: %v", ar.CurrentBlockHeight)

	// Scan through command line arguments.

	switch action {
	case "inventory":
		err = c.inventory()
	case "tally":
		err = c.tally(args[1:])
	case "vote":
		err = c.vote(args[1:])
	case "verify":
		err = c.verify(args[1:])
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
