// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sort"
	"strings"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
)

func printComment(c cmv1.Comment) {
	downvotes := int64(c.Downvotes) * -1

	printf("Comment %v\n", c.CommentID)
	printf("  Score        : %v %v\n", downvotes, c.Upvotes)
	printf("  Username     : %v\n", c.Username)
	printf("  Parent ID    : %v\n", c.ParentID)
	printf("  Timestamp    : %v\n", dateAndTimeFromUnix(c.Timestamp))

	// If the comment is an author update print extra data info
	if c.ExtraDataHint != "" {
		printf("  ExtraDataHint: %v\n", c.ExtraDataHint)
		printf("  ExtraData    : %v\n", c.ExtraData)
	}

	// If the comment has been deleted the comment text will not be
	// present. Print the reason for deletion instead and exit.
	if c.Deleted {
		printf("  Deleted      : %v\n", c.Deleted)
		printf("  Reason       : %v\n", c.Reason)
		return
	}

	// Print the fist line as is if its less than the 80 character
	// limit (including the leading comment label).
	if len(c.Comment) < 66 {
		printf("  Comment      : %v\n", c.Comment)
		return
	}

	// Format lines as 80 characters that start with two spaces.
	var b strings.Builder
	b.WriteString("  ")
	for i, v := range c.Comment {
		if i != 0 && i%78 == 0 {
			b.WriteString("\n")
			b.WriteString("  ")
		}
		b.WriteString(string(v))
	}
	printf("  Comment  :\n")
	printf("%v\n", b.String())
}

func printCommentVotes(votes []cmv1.CommentVote) {
	if len(votes) == 0 {
		return
	}
	printf("Token   : %v\n", votes[0].Token)
	printf("UserID  : %v\n", votes[0].UserID)
	printf("Username: %v\n", votes[0].Username)
	printf("Votes\n")

	// Order votes by timestamp. Oldest to newest.
	sort.SliceStable(votes, func(i, j int) bool {
		return votes[i].Timestamp < votes[j].Timestamp
	})

	for _, v := range votes {
		printf("  %-22v comment %v vote %v\n",
			dateAndTimeFromUnix(v.Timestamp), v.CommentID, v.Vote)
	}
}
