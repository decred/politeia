// Copyright (c) 2018-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	pb "github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	fmt.Fprintf(os.Stderr, "  inventory          - Retrieve all proposals"+
		" that are being voted on\n")
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

// verifyMessage verifies a message is properly signed.
// Copied from https://github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func verifyMessage(address, message, signature string) (bool, error) {
	// Decode the provided address.
	addr, err := dcrutil.DecodeAddress(address)
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
	pk, wasCompressed, err := secp256k1.RecoverCompact(sig,
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
	return a.EncodeAddress() == address, nil
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

func newClient(cfg *config) (*ctx, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
		Dial:            cfg.dial,
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
	conn, err := grpc.Dial(cfg.WalletHost,
		grpc.WithTransportCredentials(creds))
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
	if _, ok := err.(*url.Error); ok {
		return nil, errRetry
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	log.Tracef("Response: %v %v", r.StatusCode, string(responseBody))
	if r.StatusCode == http.StatusGatewayTimeout {
		return nil, errRetry
	}
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil && ue.ErrorCode != 0 {
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
		ctres, err := c.wallet.CommittedTickets(c.ctx,
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

		// Display vote bits
		fmt.Printf("Vote: %v\n", v.StartVote.Vote.Token)
		fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
		fmt.Printf("  Start block     : %v\n", v.StartVoteReply.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", v.StartVoteReply.EndHeight)
		fmt.Printf("  Mask            : %v\n", v.StartVote.Vote.Mask)
		fmt.Printf("  Eligible tickets: %v\n", len(ctres.TicketAddresses))
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

var (
	errRetry  = errors.New("retry")
	errIgnore = errors.New("ignore")
)

// sendVote expects a single vote inside the Ballot structure. It sends the
// vote off and returns the CastVoteReply for the single vote that came in.
// Function can return errRetry or errIgnore such that the caller knows if the
// command should be retried or ignored.
func (c *ctx) sendVote(ballot *v1.Ballot) (*v1.CastVoteReply, error) {
	if len(ballot.Votes) != 1 {
		return nil, fmt.Errorf("sendVote: only one vote allowed")
	}

	responseBody, err := c.makeRequest("POST", v1.RouteCastVotes, ballot)
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

// _voteTrickler trickles votes to the server. The idea here is to not issue
// large number of votes in one go to the server at the same time giving away
// which IP address owns what votes.
func (c *ctx) _voteTrickler(token, voteBit string, ctres *pb.CommittedTicketsResponse, smr *pb.SignMessagesResponse) ([]string, *v1.BallotReply, error) {
	// voteInterval is an internal structure that is used to precalculate
	// all timing intervals and vote details.
	type voteInterval struct {
		vote  v1.CastVote   // RPC vote
		votes int           // Always 1 for now
		total time.Duration // Cumulative time
		at    time.Duration // Delay to fire off vote
	}
	votes := uint64(len(ctres.TicketAddresses))
	duration := c.cfg.voteDuration
	maxDelay := uint64(duration.Seconds() / float64(votes) * 2)
	minAvgInterval := uint64(35)
	fmt.Printf("Votes       : %v\n", votes)
	fmt.Printf("Duration    : %v\n", duration)
	fmt.Printf("Avg Interval: %v\n", time.Duration(maxDelay/2)*time.Second)

	// Ensure that the duration allows for sufficiently randomized delays
	// in between votes
	if duration.Seconds() < float64(minAvgInterval)*float64(votes) {
		return nil, nil, fmt.Errorf("Vote duration must be at least %v",
			time.Duration(float64(minAvgInterval)*float64(votes))*time.Second)
	}

	// Create array of work to be done. Vote delays are random durations
	// between [0, maxDelay] (exclusive) which means that the vote delay
	// average will converge to slightly less than duration/votes as the
	// number of votes increases. Vote duration is treated as a hard cap
	// and can not be exceeded.
	buckets := make([]voteInterval, votes)
	var (
		done    bool
		retries int
	)
	maxRetries := 100
	for retries = 0; !done && retries < maxRetries; retries++ {
		done = true
		var total time.Duration
		for i := 0; i < len(buckets); i++ {
			seconds, err := util.RandomUint64()
			if err != nil {
				return nil, nil, err
			}
			seconds %= maxDelay
			if i == 0 {
				// We always immediately vote the first time
				// around. This should help catch setup errors.
				seconds = 0
			}

			// Assemble missing vote bits
			h, err := chainhash.NewHash(ctres.TicketAddresses[i].Ticket)
			if err != nil {
				return nil, nil, err
			}
			signature := hex.EncodeToString(smr.Replies[i].Signature)

			t := time.Duration(seconds) * time.Second
			total += t
			buckets[i] = voteInterval{
				vote: v1.CastVote{
					Token:     token,
					Ticket:    h.String(),
					VoteBit:   voteBit,
					Signature: signature,
				},
				votes: 1,
				total: total,
				at:    t,
			}

			// Make sure we are not going over our allotted time.
			if total > duration {
				done = false
				break
			}
		}
	}
	if retries >= maxRetries {
		// This should not happen
		return nil, nil, fmt.Errorf("Could not randomize vote delays")
	}

	// Sanity
	if len(buckets) != len(ctres.TicketAddresses) {
		return nil, nil, fmt.Errorf("unexpected time bucket count got "+
			"%v, wanted %v", len(ctres.TicketAddresses),
			len(buckets))
	}

	// Synthesize reply
	vr := v1.BallotReply{
		Receipts: make([]v1.CastVoteReply, len(ctres.TicketAddresses)),
	}
	tickets := make([]string, len(ctres.TicketAddresses))
	for i := 0; ; {
		verb := "Next vote"
		var delay time.Duration

		fmt.Printf("Voting: %v/%v %v\n", i+1, len(buckets),
			buckets[i].vote.Ticket)

		// Send off vote
		b := v1.Ballot{Votes: []v1.CastVote{buckets[i].vote}}
		br, err := c.sendVote(&b)
		switch {
		case err == errRetry:
			// Retry vote
			delay = time.Second * 44 // PNOOMA
			verb = "Retry vote"
		case err == nil || err == errIgnore:
			if err != nil {
				// Complain
				fmt.Printf("Ignoring failed vote: %v\n",
					buckets[i].vote.Ticket)
			}
			// Fill in synthesized Receipts
			if br != nil {
				vr.Receipts[i] = *br
			} else {
				// We may have to make the error a bit more
				// readable here
				vr.Receipts[i] = v1.CastVoteReply{
					Error: "Ignored",
				}
			}
			// Append ticket to return value
			tickets[i] = buckets[i].vote.Ticket

			// Next delay
			if len(buckets) == i+1 {
				// And we are done
				return tickets, &vr, nil
			}
			delay = buckets[i+1].at

			// Go to next vote
			i++
		default:
			// Fatal error
			return nil, nil, fmt.Errorf("unrecoverable error: %v",
				err)
		}

		fmt.Printf("%s at %v (delay %v)\n", verb,
			time.Now().Add(delay).Format(time.Stamp), delay)

		time.Sleep(delay)
	}
}

// verifyV1Vote verifies the signature of the passed in v1 vote. If the
// signature is invalid or if an error occurs during validation, the error will
// be logged instead of being returned. This is to prevent interuptions to
// politeavoter while it is in the process of casting votes.
func verifyV1Vote(address string, vote *v1.CastVote) bool {
	sig, err := hex.DecodeString(vote.Signature)
	if err != nil {
		log.Errorf("Could not decode signature %v: %v",
			vote.Ticket, err)
		return false
	}

	msg := vote.Token + vote.Ticket + vote.VoteBit
	validated, err := verifyMessage(address, msg,
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

func (c *ctx) _vote(seed int64, token, voteId string) ([]string, *v1.BallotReply, error) {
	// _tally provides the eligible tickets snapshot as well as a list of
	// the votes that have already been cast. We use these to filter out
	// the tickets that have already voted.
	vrr, err := c._tally(token)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("vote id not found: %v",
			voteId)
	}

	// Find eligble tickets
	tix, err := convertTicketHashes(vrr.StartVoteReply.EligibleTickets)
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

	// Put cast votes into a map so that we can
	// filter in linear time
	castVotes := make(map[string]v1.CastVote)
	for _, v := range vrr.CastVotes {
		castVotes[v.Ticket] = v
	}

	// Filter out tickets that have already voted. If a ticket has
	// voted but the signature is invalid, resubmit the vote. This
	// could be caused by bad data on the server or if the server is
	// lying to the client.
	filtered := make([]*pb.CommittedTicketsResponse_TicketAddress, 0,
		len(ctres.TicketAddresses))
	for _, t := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(t.Ticket)
		if err != nil {
			return nil, nil, err
		}
		v, ok := castVotes[h.String()]
		if !ok || !verifyV1Vote(t.Address, &v) {
			filtered = append(filtered, t)
		}
	}
	filteredLen := len(filtered)
	if filteredLen == 0 {
		return nil, nil, fmt.Errorf("no eligible tickets found")
	}
	r := rand.New(rand.NewSource(seed))
	// Fisher-Yates shuffle the ticket addresses.
	for i := 0; i < filteredLen; i++ {
		// Pick a number between current index and the end.
		j := r.Intn(filteredLen-i) + i
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	ctres.TicketAddresses = filtered

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

	if c.cfg.voteDuration != 0 {
		return c._voteTrickler(token, voteBit, ctres, smr)
	}

	// Vote everything at once.

	// Note that ctres, sm and smr use the same index.
	cv := v1.Ballot{
		Votes: make([]v1.CastVote, 0, len(ctres.TicketAddresses)),
	}
	tickets := make([]string, len(ctres.TicketAddresses))
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

func (c *ctx) vote(seed int64, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("vote: not enough arguments %v", args)
	}

	tickets, cv, err := c._vote(seed, args[0], args[1])
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

func (c *ctx) login(username, password string) (*v1.LoginReply, error) {
	l := v1.Login{
		Username: username,
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
			"identityfile username password token")
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
	action := args[0]

	var seed int64
	if action == "vote" {
		seed, err = generateSeed()
		if err != nil {
			return err
		}
	}

	// Contact WWW
	c, err := firstContact(cfg)
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
	case "startvote":
		// This remains undocumented because it is for
		// testing only.
		err = c.startVote(args[1:])
	case "tally":
		err = c.tally(args[1:])
	case "vote":
		err = c.vote(seed, args[1:])
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
