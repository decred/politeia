// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

var (
	// CLI flags
	publicKey = flag.String("k", "", "server public key")
	token     = flag.String("t", "", "record censorship token")
	signature = flag.String("s", "", "record censorship signature")
)

// loadFiles loads and returns a politeiawww records v1 File for each provided
// file path.
func loadFiles(paths []string) ([]rcv1.File, error) {
	files := make([]rcv1.File, 0, len(paths))
	for _, fp := range paths {
		fp = util.CleanAndExpandPath(fp)
		mime, digest, payload, err := util.LoadFile(fp)
		if err != nil {
			return nil, err
		}
		files = append(files, rcv1.File{
			Name:    filepath.Base(fp),
			MIME:    mime,
			Digest:  digest,
			Payload: payload,
		})
	}
	return files, nil
}

// verifyCensorshipRecord verifies a censorship record signature for a politeia
// record submission. This requires passing in the server public key, the
// censorship token, the censorship record signature, and the file paths of all
// files that are part of the record.
func verifyCensorshipRecord(serverPubKey, token, signature string, filepaths []string) error {
	// Verify all args are present
	switch {
	case serverPubKey == "":
		return fmt.Errorf("server public key not provided")
	case token == "":
		return fmt.Errorf("censorship token not provided")
	case signature == "":
		return fmt.Errorf("censorship record signature not provided")
	case len(filepaths) == 0:
		return fmt.Errorf("record files not provided")
	}

	// Load record files
	files, err := loadFiles(filepaths)
	if err != nil {
		return err
	}

	// Calc merkle root of files
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	mr, err := util.MerkleRoot(digests)
	if err != nil {
		return err
	}
	merkle := hex.EncodeToString(mr[:])

	// Load identity
	pid, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}

	// Verify record
	r := rcv1.Record{
		Files: files,
		CensorshipRecord: rcv1.CensorshipRecord{
			Token:     token,
			Merkle:    merkle,
			Signature: signature,
		},
	}
	err = client.RecordVerify(r, pid.String())
	if err != nil {
		return err
	}

	fmt.Printf("Server key : %s\n", serverPubKey)
	fmt.Printf("Token      : %s\n", token)
	fmt.Printf("Merkle root: %s\n", merkle)
	fmt.Printf("Signature  : %s\n\n", signature)
	fmt.Println("Record successfully verified")

	return nil
}

var (
	// Regexps for matching file bundles downloaded from politeiagui
	expJSONFile          = `.json$`
	expRecord            = `^[0-9a-f]{16}-v[\d]{1,2}.json$`
	expRecordTimestamps  = `^[0-9a-f]{16}-v[\d]{1,2}-timestamps.json$`
	expComments          = `^[0-9a-f]{16}-comments.json$`
	expCommentTimestamps = `^[0-9a-f]{16}-comments-timestamps.json$`
	expVotes             = `^[0-9a-f]{16}-votes.json$`
	expVoteTimestamps    = `^[0-9a-f]{16}-votes-timestamps.json$`

	regexpJSONFile          = regexp.MustCompile(expJSONFile)
	regexpRecord            = regexp.MustCompile(expRecord)
	regexpRecordTimestamps  = regexp.MustCompile(expRecordTimestamps)
	regexpComments          = regexp.MustCompile(expComments)
	regexpCommentTimestamps = regexp.MustCompile(expCommentTimestamps)
	regexpVotes             = regexp.MustCompile(expVotes)
	regexpVoteTimestamps    = regexp.MustCompile(expVoteTimestamps)
)

// verifyFile verifies a data file downloaded from politeiagui. This can be
// one of the data bundles or one of the timestamp files. The file name MUST
// be the same file name that was downloaded from politeiagui.
//
// Files that this function accepts:
// Record bundle     : [token]-[version].json
// Record timestamps : [token]-[version]-timestamps.json
// Comments bundle   : [token]-comments.json
// Comment timestamps: [token]-comments-timestamps.json
// Votes bundle      : [token]-votes.json
// Vote timestamps   : [token]-votes-timestamps.json
func verifyFile(fp string) error {
	fp = util.CleanAndExpandPath(fp)
	filename := filepath.Base(fp)

	// Match file type
	switch {
	case regexpRecord.FindString(filename) != "":
		return verifyRecordBundle(fp)
	case regexpRecordTimestamps.FindString(filename) != "":
		return verifyRecordTimestamps(fp)
	case regexpComments.FindString(filename) != "":
		return verifyCommentsBundle(fp)
	case regexpCommentTimestamps.FindString(filename) != "":
		return verifyCommentTimestamps(fp)
	case regexpVotes.FindString(filename) != "":
		return verifyVotesBundle(fp)
	case regexpVoteTimestamps.FindString(filename) != "":
		return verifyVoteTimestamps(fp)
	}

	return fmt.Errorf("file not recognized")
}

func _main() error {
	// Parse CLI arguments
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		return fmt.Errorf("no arguments provided")
	}

	// Check if the user is trying to verify a record submission
	// manually. This requires passing in the server public key, the
	// censorship token, the censorship record signature, and all of
	// the record filepaths.
	manual := (*publicKey != "") || (*token != "") || (*signature != "")
	if manual {
		// The user is trying to verify manually
		return verifyCensorshipRecord(*publicKey, *token, *signature, args)
	}

	// The user is trying to verify a bundle file that was downloaded
	// from politeiagui.
	fp := args[0]
	if regexpJSONFile.FindString(fp) == "" {
		return fmt.Errorf("'%v' is not a json file", fp)
	}
	err := verifyFile(fp)
	if err != nil {
		return fmt.Errorf("ERR COULD NOT VERIFY: %v", err)
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
