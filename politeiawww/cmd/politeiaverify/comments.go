// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/client"
)

// commentsBundle represents the comments bundle that is available for download
// in politeiagui.
type commentsBundle struct {
	Comments        []cmv1.Comment `json:"comments"`
	ServerPublicKey string         `json:"serverpublickey"`
}

// verifyCommentsBundle takes the filepath of a comments bundle and verifies
// the contents of the file. This includes verifying the signature and receipt
// of each comment in the bundle. If the comment has been deleted, the original
// comment signature will not exist but the deletion signature and receipt are
// verified instead.
func verifyCommentsBundle(fp string) error {
	// Decode comments bundle
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var cb commentsBundle
	err = json.Unmarshal(b, &cb)
	if err != nil {
		return fmt.Errorf("could not unmarshal comments bundle: %v", err)
	}
	if len(cb.Comments) == 0 {
		fmt.Printf("No comments found\n")
		return nil
	}

	// Verify comment signatures and receipts
	var (
		comments int
		dels     int
	)
	for _, v := range cb.Comments {
		err := client.CommentVerify(v, cb.ServerPublicKey)
		if err != nil {
			return err
		}
		if v.Deleted {
			dels++
			continue
		}
		comments++
	}

	fmt.Printf("Record token    : %v\n", cb.Comments[0].Token)
	fmt.Printf("Comments        : %v\n", comments)
	fmt.Printf("Deleted comments: %v\n", dels)
	fmt.Printf("All signatures and receipts verified!\n")

	return nil
}

// verifyCommentTimestamps takes the filepath of a comment timestamps file and
// verifies the validity of all timestamps included in the comments v1
// TimestampsReply.
func verifyCommentTimestamps(fp string) error {
	// Decode timestamps reply
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var tr cmv1.TimestampsReply
	err = json.Unmarshal(b, &tr)
	if err != nil {
		return err
	}
	if len(tr.Comments) == 0 {
		return fmt.Errorf("no comments found")
	}

	fmt.Printf("Total comments: %v\n", len(tr.Comments))

	// Verify timestamps
	notTimestamped, err := client.CommentTimestampsVerify(tr)
	if err != nil {
		return err
	}

	// Print the IDs of the comments that have not been timestamped yet
	if len(notTimestamped) > 0 {
		// Write all comment IDs to a string
		builder := strings.Builder{}
		for i, cid := range notTimestamped {
			s := strconv.FormatUint(uint64(cid), 10)
			if i == len(notTimestamped)-1 {
				// This is the last comment ID. Don't include a comma.
				builder.WriteString(s)
				break
			}
			builder.WriteString(fmt.Sprintf("%v, ", s))
		}

		// Print results
		fmt.Printf("Comments not yet timestamped: %v\n", builder.String())
	}

	fmt.Printf("All timestamps verified!\n")

	return nil

}
