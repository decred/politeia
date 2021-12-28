// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/comments"
)

func TestCollectVoteDigestsPage(t *testing.T) {
	// Setup test data
	userIDs := []string{"user1", "user2", "user3"}
	commentIDs := []uint32{1, 2, 3}
	token := "testtoken"
	// Use page size 2 for testing
	pageSize := uint32(2)

	// Create a comment indexes map for testing with three comment IDs,
	// which has one comment vote on the first comment from "user1",
	// another two comment votes on the second second comment from
	// "user1" and "user2", and lastly another three comment votes on
	// the third comment from all three test users.
	commentIdxes := make(map[uint32]commentIndex, len(commentIDs))
	for _, commentID := range commentIDs {
		// Prepare comment index Votes map
		commentIdx := commentIndex{
			Votes: make(map[string][]voteIndex, commentID),
		}

		users := userIDs[:commentID]
		for _, userID := range users {
			be, err := convertBlobEntryFromCommentVote(comments.CommentVote{
				UserID:    userID,
				State:     comments.RecordStateVetted,
				Token:     token,
				CommentID: commentID,
				Vote:      comments.VoteUpvote,
				PublicKey: "pubkey",
				Signature: "signature",
				Timestamp: 1,
				Receipt:   "receipt",
			})
			if err != nil {
				t.Error(err)
			}
			d, err := hex.DecodeString(be.Digest)
			if err != nil {
				t.Error(err)
			}
			commentIdx.Votes[userID] = []voteIndex{
				{
					Digest: d,
					Vote:   comments.VoteUpvote,
				},
			}
		}

		commentIdxes[commentID] = commentIdx
	}

	// Setup tests
	tests := []struct {
		name                 string
		page                 uint32
		userID               string
		resultExpectedLength int
	}{
		{
			name:                 "first user's first page",
			page:                 1,
			userID:               userIDs[0],
			resultExpectedLength: 2,
		},
		{
			name:                 "first user's second page",
			page:                 2,
			userID:               userIDs[0],
			resultExpectedLength: 1,
		},
		{
			name:                 "first user's third page",
			page:                 3,
			userID:               userIDs[0],
			resultExpectedLength: 0,
		},
		{
			name:                 "second user's first page",
			page:                 1,
			userID:               userIDs[1],
			resultExpectedLength: 2,
		},
		{
			name:                 "second user's second page",
			page:                 2,
			userID:               userIDs[1],
			resultExpectedLength: 0,
		},
		{
			name:                 "third user's first page",
			page:                 1,
			userID:               userIDs[2],
			resultExpectedLength: 1,
		},
		{
			name:                 "third user's second page",
			page:                 2,
			userID:               userIDs[2],
			resultExpectedLength: 0,
		},
		{
			name:                 "all votes first page",
			page:                 1,
			userID:               "",
			resultExpectedLength: 2,
		},
		{
			name:                 "all votes second page",
			page:                 2,
			userID:               "",
			resultExpectedLength: 2,
		},
		{
			name:                 "all votes third page",
			page:                 3,
			userID:               "",
			resultExpectedLength: 2,
		},
		{
			name:                 "all votes forth page",
			page:                 4,
			userID:               "",
			resultExpectedLength: 0,
		},
		{
			name:                 "default to first page with filtering criteria",
			page:                 0,
			userID:               userIDs[2],
			resultExpectedLength: 1,
		},
		{
			name:                 "default to first page w/o filtering criteria",
			page:                 0,
			userID:               "",
			resultExpectedLength: 2,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Run test
			digests := collectVoteDigestsPage(commentIdxes, tc.userID, tc.page,
				pageSize)

			// Verify length of returned page
			if len(digests) != tc.resultExpectedLength {
				t.Errorf("unexpected result length; want %v, got %v",
					commentIdxes, digests)
			}
		})
	}
}
