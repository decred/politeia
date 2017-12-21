package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	www "github.com/decred/politeia/politeiawww/api/v1"
)

const (
	tokenWithComments    = "5cd139b1dbda13e089e4d175d8baa2658083fcf8533c2b5ccf2105027848caba"
	tokenWithoutComments = "5cd139b1dbda13e089e4d175d8baa2658083fcf8533c2b5ccf2105027848cabb"
)

// CommentsTestSuite tests the logic concerning comments. Inherits the backend setup
// and teardown, as well as all the testify suite methods from BackendTestSuite
type CommentsTestSuite struct {
	BackendTestSuite
}

func TestCommentsTestSuite(t *testing.T) {
	Run(t, new(CommentsTestSuite))
}

func (s *CommentsTestSuite) TestAddComment() {
	s.backend.initComment(tokenWithComments)

	testCases := []struct {
		name          string
		comment       www.NewComment
		userID        uint64
		expectedError error
	}{
		{
			name: "invalid comment length",
			comment: www.NewComment{
				Token:    tokenWithComments,
				ParentID: "1",
				Comment:  generateRandomString(www.PolicyMaxCommentLength + 1),
			},
			userID: 1,
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
			},
		},
		{
			name: "valid comment length",
			comment: www.NewComment{
				Token:    tokenWithComments,
				ParentID: "1",
				Comment:  "valid length",
			},
			userID:        1,
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.name, func(*testing.T) {
			reply, err := s.backend.addComment(tc.comment, tc.userID)
			s.EqualValues(tc.expectedError, err)
			if err == nil {
				s.NotNil(reply)
				s.NotZero(reply.CommentID)
			}
		})
	}
}

func (s *CommentsTestSuite) TestProcessCommentGet() {
	const text = "comment"

	s.backend.initComment(tokenWithComments)
	s.backend.initComment(tokenWithoutComments)

	// add comment - tokenWithComments
	comment := www.NewComment{
		Token:    tokenWithComments,
		ParentID: "1",
		Comment:  text,
	}
	s.backend.addComment(comment, 1)

	// testCases
	testCases := []struct {
		name          string
		token         string
		output        *www.GetCommentsReply
		expectedError error
	}{
		{
			name:  "token exists & it has comments",
			token: tokenWithComments,
			output: &www.GetCommentsReply{
				Comments: []www.Comment{{
					Token:   tokenWithComments,
					Comment: text,
				}},
			},
			expectedError: nil,
		},
		{
			name:  "token exists & it does not have comments",
			token: tokenWithoutComments,
			output: &www.GetCommentsReply{
				Comments: []www.Comment{},
			},
			expectedError: nil,
		},
		{
			name:   "token does not exist",
			token:  "does not exist",
			output: nil,
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			},
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.name, func(*testing.T) {
			reply, err := s.backend.getComments(tc.token)
			s.EqualValues(tc.expectedError, err)
			if err == nil {
				s.NotNil(reply)

				// @TODO(rgeraldes) make sure that all the struct fields have the same value
				s.Len(reply.Comments, len(tc.output.Comments))
			}
		})
	}
}

func (s *CommentsTestSuite) TestReplayCommentJournal() {
	// create a temporary journal file
	f, err := os.OpenFile(s.backend.commentJournalFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	s.NoError(err)

	// add a journal comment
	comment := BackendComment{
		CommentID: "1",
		ParentID:  "1",
		UserID:    "1",
		Timestamp: time.Now().Unix(),
		Token:     tokenWithComments,
		Comment:   "comment",
	}

	cb, err := json.Marshal(comment)
	s.NoError(err)
	s.NotZero(cb)

	_, err = fmt.Fprintf(f, "%s\n", cb)
	s.NoError(err)

	// close file
	s.NoError(f.Close())

	// load journal in memory
	s.NoError(s.backend.replayCommentJournals())

	// 1. tokenWithComments has 1 comment
	s.Len(s.backend.comments[tokenWithComments], 1)
	// 2. tokenWithoutComments has 0 comments
	s.Len(s.backend.comments[tokenWithoutComments], 0)

	s.NoError(os.RemoveAll(s.backend.commentJournalFile))
}
