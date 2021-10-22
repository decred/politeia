// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"github.com/decred/dcrd/blockchain/stake/v3"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/client"
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
func (p *piv) walletPassphrase() ([]byte, error) {
	if p.cfg.WalletPassphrase != "" {
		return []byte(p.cfg.WalletPassphrase), nil
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

// piv is the client context.
type piv struct {
	sync.RWMutex                       // retryQ lock
	ballotResults []tkv1.CastVoteReply // results of voting

	run time.Time // when this run started

	cfg *config // application config

	// https
	client    *http.Client
	id        *identity.PublicIdentity
	userAgent string

	// wallet grpc
	ctx    context.Context
	cancel context.CancelFunc
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet pb.WalletServiceClient
}

func newPiVoter(shutdownCtx context.Context, cfg *config) (*piv, error) {
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
	return &piv{
		run:    time.Now(),
		ctx:    shutdownCtx,
		creds:  creds,
		conn:   conn,
		wallet: wallet,
		cfg:    cfg,
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

func (p *piv) jsonLog(filename, token string, work ...interface{}) error {
	dir := filepath.Join(p.cfg.voteDir, token)
	os.MkdirAll(dir, 0700)

	f := filepath.Join(dir, fmt.Sprintf("%v.%v", filename, p.run.Unix()))
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

func (p *piv) makeRequest(method, api, route string, b interface{}) ([]byte, error) {
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

	fullRoute := p.cfg.PoliteiaWWW + api + route + queryParams
	log.Debugf("Request: %v %v", method, fullRoute)
	if len(requestBody) != 0 {
		log.Tracef("%v  ", string(requestBody))
	}

	// This is a hack to test this code.
	if p.cfg.testing {
		// Fake out CastBallotReply. We cast b to CastBallot but this
		// may have to change in the future if we add additional
		// functionality here.
		cbr := tkv1.CastBallotReply{
			Receipts: []tkv1.CastVoteReply{
				{
					Ticket:  b.(*tkv1.CastBallot).Votes[0].Ticket,
					Receipt: "receipt",
					//ErrorCode: tkv1.VoteErrorInvalid,
					//ErrorContext:"ec",

				},
			},
		}
		jcbr, err := json.Marshal(cbr)
		if err != nil {
			return nil, fmt.Errorf("TEST FAILED: %v", err)
		}
		return jcbr, nil
	}
	req, err := http.NewRequestWithContext(p.ctx, method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", p.userAgent)
	r, err := p.client.Do(req)
	if err != nil {
		return nil, ErrRetry{
			At:  "p.client.Do(req)",
			Err: err,
		}
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	log.Tracef("Response: %v %v", r.StatusCode, string(responseBody))

	switch r.StatusCode {
	case http.StatusOK:
		// Nothing to do. Continue.
	case http.StatusBadRequest:
		// The error was caused by the client. These will result in
		// the same error every time so should not be retried.
		var ue tkv1.UserErrorReply
		err = json.Unmarshal(responseBody, &ue)
		if err == nil && ue.ErrorCode != 0 {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				tkv1.ErrorCodes[ue.ErrorCode], ue.ErrorContext)
		}
	default:
		// Retry all other errors
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
func (p *piv) getVersion() (*v1.VersionReply, error) {
	responseBody, err := p.makeRequest(http.MethodGet,
		v1.PoliteiaWWWAPIRoute, v1.RouteVersion, nil)
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
func firstContact(shutdownCtx context.Context, cfg *config) (*piv, error) {
	// Always hit / first for to obtain the server identity and api version
	p, err := newPiVoter(shutdownCtx, cfg)
	if err != nil {
		return nil, err
	}
	version, err := p.getVersion()
	if err != nil {
		return nil, err
	}
	log.Debugf("Version: %v", version.Version)
	log.Debugf("Route  : %v", version.Route)
	log.Debugf("Pubkey : %v", version.PubKey)

	p.id, err = identity.PublicIdentityFromString(version.PubKey)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// eligibleVotes takes a vote result reply that contains the full list of the
// votes already cast along with a committed tickets response from wallet which
// consists of a list of tickets the wallet is aware of and returns a list of
// tickets that the wallet is actually able to sign and vote with.
//
// When a ticket has already voted, the signature is also checked to ensure it
// is valid.  In the case it is invalid, and the wallet can sign it, the ticket
// is included so it may be resubmitted.  This could be caused by bad data on
// the server or if the server is lying to the client.
func (p *piv) eligibleVotes(rr *tkv1.ResultsReply, ctres *pb.CommittedTicketsResponse) ([]*pb.CommittedTicketsResponse_TicketAddress, error) {
	// Put cast votes into a map to filter in linear time
	castVotes := make(map[string]tkv1.CastVoteDetails)
	for _, v := range rr.Votes {
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
		r, err := p.wallet.GetTransaction(context.TODO(), &pb.GetTransactionRequest{
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
		vr, err := p.wallet.ValidateAddress(context.TODO(), &pb.ValidateAddressRequest{
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

		_, ok := castVotes[h.String()]
		if !ok {
			eligible = append(eligible, t)
		}
	}

	return eligible, nil
}

func (p *piv) _inventory(i tkv1.Inventory) (*tkv1.InventoryReply, error) {
	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteInventory, i)
	if err != nil {
		return nil, err
	}

	var ar tkv1.InventoryReply
	err = json.Unmarshal(responseBody, &ar)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal InventoryReply: %v",
			err)
	}

	return &ar, nil
}

// voteDetails sends ticketvote API Details request, then verifies and
// returns the reply.
func (p *piv) voteDetails(token, serverPubKey string) (*tkv1.DetailsReply, error) {
	d := tkv1.Details{
		Token: token,
	}
	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteDetails, d)
	if err != nil {
		return nil, err
	}

	var dr tkv1.DetailsReply
	err = json.Unmarshal(responseBody, &dr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal DetailsReply: %v",
			err)
	}

	// Verify VoteDetails.
	err = client.VoteDetailsVerify(*dr.Vote, serverPubKey)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

func (p *piv) voteResults(token, serverPubKey string) (*tkv1.ResultsReply, error) {
	r := tkv1.Results{
		Token: token,
	}
	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteResults, r)
	if err != nil {
		return nil, err
	}

	var rr tkv1.ResultsReply
	err = json.Unmarshal(responseBody, &rr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ResultsReply: %v", err)
	}

	// Verify CastVoteDetails.
	for _, cvd := range rr.Votes {
		err = client.CastVoteDetailsVerify(cvd, serverPubKey)
		if err != nil {
			return nil, err
		}
	}

	return &rr, nil
}

func (p *piv) inventory() error {
	// Get server public key to verify replies.
	version, err := p.getVersion()
	if err != nil {
		return err
	}
	serverPubKey := version.PubKey
	// Inventory route is paginated, therefore we keep fetching
	// until we receive a patch with number of records smaller than the
	// ticketvote's declared page size.
	page := uint32(1)
	var tokens []string
	for {
		ir, err := p._inventory(tkv1.Inventory{
			Page:   page,
			Status: tkv1.VoteStatusStarted,
		})
		if err != nil {
			return err
		}
		pageTokens := ir.Vetted[tkv1.VoteStatuses[tkv1.VoteStatusStarted]]
		tokens = append(tokens, pageTokens...)
		if uint32(len(pageTokens)) < tkv1.InventoryPageSize {
			break
		}
		page++
	}

	// Print empty message in case no active votes found.
	if len(tokens) == 0 {
		fmt.Printf("No active votes found.\n")
		return nil
	}

	for _, t := range tokens {
		// Get vote details.
		dr, err := p.voteDetails(t, serverPubKey)
		if err != nil {
			return err
		}

		// Ensure eligibility
		tix, err := convertTicketHashes(dr.Vote.EligibleTickets)
		if err != nil {
			fmt.Printf("Ticket pool corrupt: %v %v\n",
				dr.Vote.Params.Token, err)
			continue
		}
		ctres, err := p.wallet.CommittedTickets(p.ctx,
			&pb.CommittedTicketsRequest{
				Tickets: tix,
			})
		if err != nil {
			fmt.Printf("Ticket pool verification: %v %v\n",
				dr.Vote.Params.Token, err)
			continue
		}

		// Bail if there are no eligible tickets
		if len(ctres.TicketAddresses) == 0 {
			fmt.Printf("No eligible tickets: %v\n", dr.Vote.Params.Token)
		}

		// voteResults provides a list of the votes that have already been cast.
		// Use these to filter out the tickets that have already voted.
		rr, err := p.voteResults(dr.Vote.Params.Token, serverPubKey)
		if err != nil {
			fmt.Printf("Failed to obtain vote results for %v: %v\n",
				dr.Vote.Params.Token, err)
			continue
		}

		// Filter out tickets that have already voted or are otherwise
		// ineligible for the wallet to sign.  Note that tickets that have
		// already voted, but have an invalid signature are included so they
		// may be resubmitted.
		eligible, err := p.eligibleVotes(rr, ctres)
		if err != nil {
			fmt.Printf("Eligible vote filtering error: %v %v\n",
				dr.Vote.Params, err)
			continue
		}

		// Display vote bits
		fmt.Printf("Vote: %v\n", dr.Vote.Params.Token)
		fmt.Printf("  Start block     : %v\n", dr.Vote.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", dr.Vote.EndBlockHeight)
		fmt.Printf("  Mask            : %v\n", dr.Vote.Params.Mask)
		fmt.Printf("  Eligible tickets: %v\n", len(ctres.TicketAddresses))
		fmt.Printf("  Eligible votes  : %v\n", len(eligible))
		for _, vo := range dr.Vote.Params.Options {
			fmt.Printf("  Vote Option:\n")
			fmt.Printf("    Id                   : %v\n", vo.ID)
			fmt.Printf("    Description          : %v\n",
				vo.Description)
			fmt.Printf("    Bit                 : %v\n", vo.Bit)
			fmt.Printf("    To choose this option: "+
				"politeiavoter vote %v %v\n", dr.Vote.Params.Token,
				vo.ID)
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
func (p *piv) sendVoteFail(ballot *tkv1.CastBallot) (*tkv1.CastVoteReply, error) {
	return nil, ErrRetry{
		At: "sendVoteFail",
	}
}

func (p *piv) sendVote(ballot *tkv1.CastBallot) (*tkv1.CastVoteReply, error) {
	if len(ballot.Votes) != 1 {
		return nil, fmt.Errorf("sendVote: only one vote allowed")
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteCastBallot, ballot)
	if err != nil {
		return nil, err
	}

	var vr tkv1.CastBallotReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"CastVoteReply: %v", err)
	}
	if len(vr.Receipts) != 1 {
		// Should be impossible
		return nil, fmt.Errorf("sendVote: invalid receipt count %v",
			len(vr.Receipts))
	}

	return &vr.Receipts[0], nil
}

// dumpComplete dumps the completed votes in this run.
func (p *piv) dumpComplete() {
	p.RLock()
	defer p.RUnlock()

	fmt.Printf("Completed votes (%v):\n", len(p.ballotResults))
	for _, v := range p.ballotResults {
		fmt.Printf("  %v %v\n", v.Ticket, v.ErrorCode)
	}
}

func (p *piv) dumpQueue() {
	p.RLock()
	defer p.RUnlock()

	panic("dumpQueue")
}

// dumpTogo dumps the votes that have not been casrt yet.
func (p *piv) dumpTogo() {
	p.RLock()
	defer p.RUnlock()

	panic("dumpTogo")
}

func (p *piv) _vote(token, voteID string) error {
	passphrase, err := p.walletPassphrase()
	if err != nil {
		return err
	}
	// This assumes the account is an HD account.
	_, err = p.wallet.GetAccountExtendedPrivKey(p.ctx,
		&pb.GetAccountExtendedPrivKeyRequest{
			AccountNumber: 0, // TODO: make a config flag
			Passphrase:    passphrase,
		})
	if err != nil {
		return err
	}

	seed, err := generateSeed()
	if err != nil {
		return err
	}

	// Verify vote is still active
	sr, err := p._summary(token)
	if err != nil {
		return err
	}
	vs, ok := sr.Summaries[token]
	if !ok {
		return fmt.Errorf("proposal does not exist: %v", token)
	}
	if vs.Status != tkv1.VoteStatusStarted {
		return fmt.Errorf("proposal vote is not active: %v", vs.Status)
	}
	bestBlock := vs.BestBlock

	// Get server public key by calling version request.
	v, err := p.getVersion()
	if err != nil {
		return err
	}

	// Get vote details.
	dr, err := p.voteDetails(token, v.PubKey)
	if err != nil {
		return err
	}

	// Validate voteId
	var (
		voteBit string
		found   bool
	)
	for _, vv := range dr.Vote.Params.Options {
		if vv.ID == voteID {
			found = true
			voteBit = strconv.FormatUint(vv.Bit, 16)
			break
		}
	}
	if !found {
		return fmt.Errorf("vote id not found: %v", voteID)
	}

	// Find eligble tickets
	tix, err := convertTicketHashes(dr.Vote.EligibleTickets)
	if err != nil {
		return fmt.Errorf("ticket pool corrupt: %v %v",
			token, err)
	}
	ctres, err := p.wallet.CommittedTickets(p.ctx,
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

	// voteResults a list of the votes that have already been cast. We use these
	// to filter out the tickets that have already voted.
	rr, err := p.voteResults(token, v.PubKey)
	if err != nil {
		return err
	}

	// Filter out tickets that have already voted or are otherwise ineligible
	// for the wallet to sign.  Note that tickets that have already voted, but
	// have an invalid signature are included so they may be resubmitted.
	eligible, err := p.eligibleVotes(rr, ctres)
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
	smr, err := p.wallet.SignMessages(p.ctx, sm)
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

	if p.cfg.Trickle {
		go p.statsHandler()

		// Calculate vote duration if not set
		if p.cfg.voteDuration.Seconds() == 0 {
			blocksLeft := int64(vs.EndBlockHeight) - int64(bestBlock)
			if blocksLeft < int64(p.cfg.HoursPrior*p.cfg.blocksPerHour) {
				return fmt.Errorf("less than twelve hours " +
					"left to vote, please set " +
					"--voteduration manually")
			}
			p.cfg.voteDuration = activeNetParams.TargetTimePerBlock *
				(time.Duration(blocksLeft) -
					time.Duration(p.cfg.HoursPrior*p.cfg.blocksPerHour))
		}

		return p.alarmTrickler(token, voteBit, ctres, smr)
	}

	// Vote everything at once.

	// Note that ctres, sm and smr use the same index.
	cv := tkv1.CastBallot{
		Votes: make([]tkv1.CastVote, 0, len(ctres.TicketAddresses)),
	}
	p.ballotResults = make([]tkv1.CastVoteReply, 0, len(ctres.TicketAddresses))
	for k, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)
		cv.Votes = append(cv.Votes, tkv1.CastVote{
			Token:     token,
			Ticket:    h.String(),
			VoteBit:   voteBit,
			Signature: signature,
		})
	}

	// Vote on the supplied proposal
	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteCastBallot, &cv)
	if err != nil {
		return err
	}

	var br tkv1.CastBallotReply
	err = json.Unmarshal(responseBody, &br)
	if err != nil {
		return fmt.Errorf("Could not unmarshal CastVoteReply: %v",
			err)
	}
	p.ballotResults = br.Receipts

	return nil
}

func (p *piv) vote(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("vote: not enough arguments %v", args)
	}

	err := p._vote(args[0], args[1])
	if err != nil {
		return err
	}

	// Verify vote replies
	failedReceipts := make([]tkv1.CastVoteReply, 0,
		len(p.ballotResults))
	for _, v := range p.ballotResults {
		if v.ErrorContext != "" {
			failedReceipts = append(failedReceipts, v)
			continue
		}
	}
	fmt.Printf("Votes succeeded: %v\n", len(p.ballotResults)-
		len(failedReceipts))
	fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
	notCast := 111111
	if notCast > 0 {
		fmt.Printf("Votes not cast : %v (FIXME)\n", notCast)
	}
	for _, v := range failedReceipts {
		fmt.Printf("Failed vote    : %v %v\n",
			v.Ticket, v.ErrorContext)
	}

	return nil
}

func (p *piv) _summary(token string) (*tkv1.SummariesReply, error) {
	responseBody, err := p.makeRequest(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteSummaries,
		tkv1.Summaries{Tokens: []string{token}})
	if err != nil {
		return nil, err
	}

	var sr tkv1.SummariesReply
	err = json.Unmarshal(responseBody, &sr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal SummariesReply: %v", err)
	}

	return &sr, nil
}

func (p *piv) tally(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("tally: not enough arguments %v", args)
	}

	// Get server public key by calling version.
	v, err := p.getVersion()
	if err != nil {
		return err
	}

	token := args[0]
	t, err := p.voteResults(token, v.PubKey)
	if err != nil {
		return err
	}

	// tally votes
	count := make(map[uint64]uint)
	var total uint
	for _, v := range t.Votes {
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

	// Get vote details to dump vote options.
	dr, err := p.voteDetails(token, v.PubKey)
	if err != nil {
		return err
	}

	// Dump
	for _, vo := range dr.Vote.Params.Options {
		fmt.Printf("Vote Option:\n")
		fmt.Printf("  Id                   : %v\n", vo.ID)
		fmt.Printf("  Description          : %v\n",
			vo.Description)
		fmt.Printf("  Bit                  : %v\n", vo.Bit)
		vr := count[vo.Bit]
		fmt.Printf("  Votes received       : %v\n", vr)
		if total == 0 {
			continue
		}
		fmt.Printf("  Percentage           : %v%%\n",
			(float64(vr))/float64(total)*100)
	}

	return nil
}

type failedTuple struct {
	Time  JSONTime
	Votes tkv1.CastBallot `json:"votes"`
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
	Result tkv1.CastVoteReply
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
	Votes []voteAlarm
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

func (p *piv) verifyVote(vote string) error {
	// Vote directory
	dir := filepath.Join(p.cfg.voteDir, vote)

	// See if vote is ongoing
	vsr, err := p._summary(vote)
	if err != nil {
		return fmt.Errorf("could not obtain proposal status: %v",
			err)
	}
	vs, ok := vsr.Summaries[vote]
	if !ok {
		return fmt.Errorf("proposal does not exist: %v", vote)
	}
	if vs.Status != tkv1.VoteStatusFinished &&
		vs.Status != tkv1.VoteStatusRejected &&
		vs.Status != tkv1.VoteStatusApproved {
		return fmt.Errorf("proposal vote not finished: %v",
			tkv1.VoteStatuses[vs.Status])
	}

	// Get server public key.
	v, err := p.getVersion()
	if err != nil {
		return err
	}

	// Get and cache vote results.
	voteResultsFilename := filepath.Join(dir, ".voteresults")
	if !util.FileExists(voteResultsFilename) {
		rr, err := p.voteResults(vote, v.PubKey)
		if err != nil {
			return fmt.Errorf("failed to obtain vote results "+
				"for %v: %v\n", vote, err)
		}
		f, err := os.Create(voteResultsFilename)
		if err != nil {
			return fmt.Errorf("create cache: %v", err)
		}
		e := json.NewEncoder(f)
		err = e.Encode(rr)
		if err != nil {
			f.Close()
			_ = os.Remove(voteResultsFilename)
			return fmt.Errorf("encode cache: %v", err)
		}
		f.Close()
	}

	// Open cached vote results.
	f, err := os.Open(voteResultsFilename)
	if err != nil {
		return fmt.Errorf("open cache: %v", err)
	}
	d := json.NewDecoder(f)
	var rr tkv1.ResultsReply
	err = d.Decode(&rr)
	if err != nil {
		f.Close()
		return fmt.Errorf("decode cache: %v", err)
	}
	f.Close()

	// Get vote details.
	dr, err := p.voteDetails(vote, v.PubKey)
	if err != nil {
		return fmt.Errorf("failed to obtain vote details "+
			"for %v: %v\n", vote, err)
	}

	// Index vote results for more vroom vroom
	eligible := make(map[string]string,
		len(dr.Vote.EligibleTickets))
	for _, v := range dr.Vote.EligibleTickets {
		eligible[v] = "" // XXX
	}
	cast := make(map[string]string, len(rr.Votes))
	for _, v := range rr.Votes {
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

func (p *piv) verify(args []string) error {
	// Override 0 to list all possible votes.
	if len(args) == 0 {
		fa, err := ioutil.ReadDir(p.cfg.voteDir)
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
		fa, err := ioutil.ReadDir(p.cfg.voteDir)
		if err != nil {
			return err
		}
		for k := range fa {
			_, err := hex.DecodeString(fa[k].Name())
			if err != nil {
				continue
			}

			err = p.verifyVote(fa[k].Name())
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

		err = p.verifyVote(args[k])
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
	ar, err := c.wallet.Accounts(c.ctx, &pb.AccountsRequest{})
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
		// Print the error to stderr if the logs have not been
		// setup yet.
		if logRotator == nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		} else {
			log.Error(err)
		}
		os.Exit(1)
	}
}
