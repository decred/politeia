// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdVoteResults retreives the cast ticket votes for a record.
type cmdVoteResults struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`

	// Save instructs the command to save the vote results to the
	// current working directory as a CSV file.
	Save bool `long:"save" optional:"true"`

	// Filter can be used to instruct the command to only save a
	// specific vote option to disk when using the --save flag.
	// The vote option should be specified using the hex encoded
	// vote bit.
	// Ex: --filter=1
	Filter string `long:"filter" optional:"true"`
}

// Execute executes the cmdVoteResults command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteResults) Execute(args []string) error {
	// Verify command options
	switch {
	case !c.Save && c.Filter != "":
		return fmt.Errorf("--filter can only be used in conjunction with --save")
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert: cfg.HTTPSCert,
		Verbose:   cfg.Verbose,
		RawJSON:   cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Get vote results
	r := tkv1.Results{
		Token: c.Args.Token,
	}
	rr, err := pc.TicketVoteResults(r)
	if err != nil {
		return err
	}

	// Save vote results to disk if --save flag has been provided.
	if c.Save {
		return saveVoteResults(r.Token, rr, c.Filter)
	}

	// Print results summary
	printVoteResults(rr.Votes)

	return nil
}

// saveVoteResults saves the provided vote results to disk as a csv file. The
// filter argument can be provided if the user wants to filter out a specific
// vote option and only save that vote options to disk. The filter argument
// should match the hex encoded vote bit.
func saveVoteResults(token string, rr *tkv1.ResultsReply, filter string) error {
	// Setup the file path
	filename := fmt.Sprintf("%v-voteresults.csv", token)
	if filter != "" {
		filename = fmt.Sprintf("%v-voteresults-%v.csv", token, filter)
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	path := filepath.Join(wd, filename)

	// Open the file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write votes to file buffer
	w := bufio.NewWriter(f)
	w.WriteString("token,ticket,votebit,address,signature,receipt,timestamp\n")

	for _, v := range rr.Votes {
		// A filter can be provided if the user only wants
		// to save one of the vote options to disk.
		if filter != "" && filter != v.VoteBit {
			// This is not the specified vote option
			continue
		}

		// Add the cast vote to the buffer
		w.WriteString(fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n",
			v.Token, v.Ticket, v.VoteBit, v.Address,
			v.Signature, v.Receipt, v.Timestamp))
	}

	// Write the buffer to disk
	w.Flush()

	printf("File saved: %v\n", path)

	return nil
}

// voteResultsHelpMsg is printed to stdout by the help command.
const voteResultsHelpMsg = `voteresults "token"

Fetch vote results for a record.

Arguments:
1. token  (string, required)  Record token.

Flags:
 --save   (bool)    Save instructs the command to save the vote results to the
                    current working directory as a CSV file.

 --filter (string)  Filter can be used to instruct the command to only save a
                    specific vote option to disk when using the --save flag.
                    The vote option should be specified using the hex encoded
                    vote bit.
                    Ex: --filter=1
`
