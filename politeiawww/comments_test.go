package main

import (
	"io/ioutil"
	"os"
	"testing"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/stretchr/testify/suite"
)

func TestCommentsTestSuite(t *testing.T) {
	suite.Run(t, new(CommentsTestSuite))
}

type CommentsTestSuite struct {
	suite.Suite
	dataDir string
	backend *backend
	token   string
}

func (s *CommentsTestSuite) SetupSuite() {
	s.token = "5cd139b1dbda13e089e4d175d8baa2658083fcf8533c2b5ccf2105027848caba"
}

func (s *CommentsTestSuite) SetupTest() {

	require := s.Require()

	//@rgeraldes - this logic should be part of the backend
	dir, err := ioutil.TempDir("", "politeiawww.test")
	require.NoError(err)
	require.NotNil(dir)
	s.dataDir = dir

	// setup backend
	backend, err := NewBackend(&config{DataDir: dir})
	require.NoError(err)
	require.NotNil(backend)
	backend.test = true
	s.backend = backend

	// init comment map
	s.backend.initComment(s.token)
}

func (s *CommentsTestSuite) AfterTest(suiteName, testName string) {
	require := s.Require()

	// close db
	require.NoError(s.backend.db.Close())

	// remove data dir
	require.NoError(os.RemoveAll(s.dataDir))
}

func (s *CommentsTestSuite) TestAddComment() {
	const (
		testToken = 1
	)

	require := s.Require()

	testCases := []struct {
		comment       www.NewComment
		userID        uint64
		expectedError error
	}{
		// invalid comment length
		{
			comment: www.NewComment{
				Token:    s.token,
				ParentID: "1",
				Comment:  generateRandomString(www.PolicyMaxCommentLength + 1),
			},
			userID: 1,
			expectedError: www.UserError{
				ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
			},
		},
		// valid comment length
		{
			comment: www.NewComment{
				Token:    s.token,
				ParentID: "1",
				Comment:  "valid length",
			},
			userID:        1,
			expectedError: nil,
		},
	}

	for _, testCase := range testCases {
		reply, err := s.backend.addComment(testCase.comment, testCase.userID)
		require.EqualValues(testCase.expectedError, err)
		if err == nil {
			require.NotNil(reply)
			require.NotZero(reply.CommentID)
		}
	}

}
