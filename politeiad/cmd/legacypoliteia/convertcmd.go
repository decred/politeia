// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	dcrdata "github.com/decred/dcrdata/v6/api/types"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

const (
	// Default command settings
	defaultLegacyDir = "./legacy-politeia-data"

	// filePermissions is the file permissions that are used for all directory
	// and file creation in this tool.
	filePermissions = 0755
)

var (
	// CLI flags for the convert command
	convertFlags = flag.NewFlagSet(convertCmdName, flag.ContinueOnError)
	legacyDir    = convertFlags.String("legacydir", defaultLegacyDir,
		"default legacy data dir")
	skipComments = convertFlags.Bool("skipcomments", false, "skip comments")
	skipBallots  = convertFlags.Bool("skipballots", false, "skip ballots")
	ballotLimit  = convertFlags.Int("ballotlimit", 0, "limit parsed votes")
	token        = convertFlags.String("token", "", "test one proposal at a time")
)

type convertCmd struct {
	client       *http.Client
	gitRepo      string
	legacyDir    string
	skipComments bool
	skipBallots  bool
	ballotLimit  int
	token        string
}

// execConvertComd executes the convert command.
//
// The convert command parses a legacy git repo, converts the data into types
// supported by the tstore backend, then writes the converted JSON data to
// disk. This data can be imported into tstore using the 'import' command.
func execConvertCmd(args []string) error {
	// Verify the git repo exists
	if len(args) == 0 {
		return fmt.Errorf("missing git repo argument")
	}
	gitRepo := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(gitRepo); err != nil {
		return fmt.Errorf("git repo not found: %v", gitRepo)
	}

	// Parse the CLI flags
	err := convertFlags.Parse(args[1:])
	if err != nil {
		return err
	}

	// Clean the legacy directory path
	*legacyDir = util.CleanAndExpandPath(*legacyDir)

	// Setup the legacy directory
	err = os.MkdirAll(*legacyDir, filePermissions)
	if err != nil {
		return err
	}

	client, err := util.NewHTTPClient(false, "")
	if err != nil {
		return err
	}

	// Setup the cmd context
	c := convertCmd{
		client:       client,
		gitRepo:      gitRepo,
		legacyDir:    *legacyDir,
		skipComments: *skipComments,
		skipBallots:  *skipBallots,
		ballotLimit:  *ballotLimit,
		token:        *token,
	}

	// Convert the git proposals
	return c.convertGitProposals()
}

// convertGitProposals converts the git proposals to tstore proposals, saving
// the tstore proposals to disk as the conversion is finished.
func (c *convertCmd) convertGitProposals() error {
	// Build an inventory of all git proposal tokens
	tokens, err := gitProposalTokens(c.gitRepo)
	if err != nil {
		return err
	}

	fmt.Printf("Found %v legacy git proposals\n", len(tokens))

	if c.token != "" {
		fmt.Printf("Single token filter is used: %v\n", c.token)
	}

	// Convert the data for each proposal into tstore supported types.
	count := 1
	for token := range tokens {
		switch {
		case c.token != "" && c.token != token:
			// The caller only wants to convert a single
			// proposal and this is not it. Skip it.
			continue

		case c.token != "" && c.token == token:
			// The caller only wants to convert a single
			// proposal and this is it. Convert it.
			fmt.Printf("Converting proposal %v\n", token)

		default:
			// All proposals are being converted
			fmt.Printf("Converting proposal %v (%v/%v)\n",
				token, count, len(tokens))
		}

		// Get the path to the most recent version of the proposal.
		// The version number is the directory name. We only import
		// the most recent version of the proposal.
		//
		// Example path: [gitRepo]/[token]/[version]/
		v, err := latestVersion(c.gitRepo, token)
		if err != nil {
			return err
		}

		version := strconv.FormatUint(v, 10)
		proposalDir := filepath.Join(c.gitRepo, token, version)

		// Convert git backend types to tstore backend types
		recordMD, err := convertRecordMetadata(proposalDir)
		if err != nil {
			return err
		}
		files, err := convertFiles(proposalDir)
		if err != nil {
			return err
		}
		proposalMD, err := convertProposalMetadata(proposalDir)
		if err != nil {
			return err
		}
		voteMD, err := convertVoteMetadata(proposalDir)
		if err != nil {
			return err
		}
		userMD, err := c.convertUserMetadata(proposalDir)
		if err != nil {
			return err
		}
		statusChange, err := convertStatusChange(proposalDir)
		if err != nil {
			return err
		}
		authDetails, err := convertAuthDetails(proposalDir, recordMD)
		if err != nil {
			return err
		}
		voteDetails, err := convertVoteDetails(proposalDir, voteMD)
		if err != nil {
			return err
		}

		// Convert cast vote details
		cv, err := convertCastVotes(proposalDir, c.skipBallots, c.ballotLimit)
		if err != nil {
			return err
		}

		// If converted ballot is limited, collect converted ticket hashes in
		// order to fetch their commitment addresses and vote timestamps.
		var filteredHashes []string
		if c.ballotLimit != 0 {
			filteredHashes = make([]string, 0, c.ballotLimit)
			for _, v := range cv {
				filteredHashes = append(filteredHashes, v.Ticket)
			}
		}

		// Fetch largest commitment addresses of eligible tickets
		addrs, err := c.fetchLargestCommitmentAddrs(voteDetails, c.skipBallots,
			filteredHashes)
		if err != nil {
			return err
		}

		// Parse git vote timestamps using git log. If ballots are limited skip
		// this step to speed up testing.
		var ts map[string]int64
		if c.ballotLimit == 0 && !c.skipBallots && voteDetails != nil {
			ts, err = parseVoteTimestamps(proposalDir, filteredHashes)
			if err != nil {
				return err
			}
		}

		// Populate ticket addresses and vote timestamps
		for _, v := range cv {
			v.Address = addrs[v.Ticket]
			v.Timestamp = ts[v.Ticket]

			// Verify cast vote details signature
			err = client.CastVoteDetailsVerify(convertCastVoteDetailsToV1(v),
				serverPubkey)
			if err != nil {
				return err
			}
		}

		ct, err := c.convertComments(proposalDir)
		if err != nil {
			return err
		}

		// Build the proposal
		p := proposal{
			RecordMetadata:   *recordMD,
			Files:            files,
			ProposalMetadata: *proposalMD,
			VoteMetadata:     voteMD,
			UserMetadata:     *userMD,
			StatusChange:     statusChange,
			AuthDetails:      authDetails,
			VoteDetails:      voteDetails,
			CastVotes:        cv,
			CommentAdds:      ct.Adds,
			CommentDels:      ct.Dels,
			CommentVotes:     ct.Votes,
		}

		if c.ballotLimit == 0 && !c.skipBallots && !c.skipComments {
			err = sanityChecks(&p)
			if err != nil {
				return err
			}
		}

		// Save the proposal to disk
		err = saveProposal(c.legacyDir, &p)
		if err != nil {
			return err
		}

		count++
	}

	return nil
}

// fetchLargestCommitmentAddrs fetches the largest commitment address for each
// eligible ticket from a record vote. Returns a map of ticket hash to address.
func (c *convertCmd) fetchLargestCommitmentAddrs(voteDetails *ticketvote.VoteDetails, skipBallots bool, filteredHashes []string) (map[string]string, error) {
	fmt.Printf("  Eligible ticket addresses\n")

	// If proposals has no vote details, skip ballots flag is on or no eligible
	// tickets present, skip fetching ticket addresses.
	if skipBallots || voteDetails == nil ||
		len(voteDetails.EligibleTickets) == 0 {
		return nil, nil
	}

	var tickets []string
	switch {
	// If tickets are limited, use given subset of ticket hashes
	case len(filteredHashes) != 0:
		tickets = filteredHashes

	// Otherwise, use all eligible tickets
	default:
		tickets = voteDetails.EligibleTickets
	}

	// Fetch addresses in batches of 500
	var (
		ticketsLen = len(tickets)
		addrs      = make(map[string]string, ticketsLen) // [ticket]address
		pageSize   = 500
		startIdx   int
		done       bool
	)
	for !done {
		endIdx := startIdx + pageSize
		if endIdx > ticketsLen {
			endIdx = ticketsLen
			done = true
		}

		ts := tickets[startIdx:endIdx]
		data, err := c.largestCommitmentAddrs(ts)
		if err != nil {
			return nil, err
		}

		for ticket, address := range data {
			addrs[ticket] = address
		}

		startIdx += pageSize
		printInPlace(fmt.Sprintf("    Address %v", len(addrs)))
	}
	fmt.Printf("\n")

	return addrs, nil
}

// largestCommitmentAddrs calls the dcrdata API to retrieve the largest
// commitment addresses of the given transaction hashes.
func (c *convertCmd) largestCommitmentAddrs(hashes []string) (map[string]string, error) {
	// Batch request all of the transaction info from dcrdata.
	reqBody, err := json.Marshal(dcrdata.Txns{
		Transactions: hashes,
	})
	if err != nil {
		return nil, err
	}

	// Make the POST request
	url := "https://dcrdata.decred.org/api/txs/trimmed"
	r, err := c.client.Post(url, "application/json; charset=utf-8",
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				r.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			r.StatusCode, url, body)
	}

	// Unmarshal the response
	var ttxs []dcrdata.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttxs); err != nil {
		return nil, err
	}

	// Find largest commitment address for each transaction.
	addrs := make(map[string]string, len(hashes))

	for i := range ttxs {
		// Best is address with largest commit amount.
		var bestAddr string
		var bestAmount float64
		for _, v := range ttxs[i].Vout {
			if v.ScriptPubKeyDecoded.CommitAmt == nil {
				continue
			}
			if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
				if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
					continue
				}
				bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
				bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
			}
		}

		if bestAddr == "" || bestAmount == 0.0 {
			return nil, fmt.Errorf("no best commitment address found: %v",
				ttxs[i].TxID)
		}
		addrs[ttxs[i].TxID] = bestAddr
	}

	return addrs, nil
}

// sanityChecks performs some basic sanity checks on the proposal data.
func sanityChecks(p *proposal) error {
	switch {
	case len(p.Files) == 0:
		return fmt.Errorf("no files found")
	case p.ProposalMetadata.Name == "":
		return fmt.Errorf("proposal name missing")
	case p.UserMetadata.UserID == "":
		return fmt.Errorf("user id missing")
	}

	// Checks based on record status
	switch p.RecordMetadata.Status {
	case backend.StatusArchived:
		// Archived proposals will have two status
		// changes and no vote data, we convert the latest
		// status change.
		if p.StatusChange == nil {
			return fmt.Errorf("invalid status change")
		}
		if p.AuthDetails != nil {
			return fmt.Errorf("auth details invalid")
		}
		if p.VoteDetails != nil {
			return fmt.Errorf("vote details invalid")
		}
		if len(p.CastVotes) != 0 {
			return fmt.Errorf("cast votes invalid")
		}

	case backend.StatusPublic:
		// All non-archived proposals will be public,
		// with a single status change, and will have
		// the vote data populated.
		if p.StatusChange == nil {
			return fmt.Errorf("invalid status change")
		}
		if p.AuthDetails == nil {
			return fmt.Errorf("auth details missing")
		}
		if p.VoteDetails == nil {
			return fmt.Errorf("vote details missing")
		}
		if len(p.CastVotes) == 0 {
			return fmt.Errorf("cast votes missing")
		}

	default:
		return fmt.Errorf("unknown record status")
	}

	return nil
}
