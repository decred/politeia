package main

import (
	"os"
	"testing"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/stretchr/testify/suite"
)

type commentTestCase struct {
	comment       www.NewComment
	userID        uint64
	expectedError error
}

func TestCommentsTestSuite(t *testing.T) {
	cts := CommentsTestSuite{
		t: t,
	}
	suite.Run(t, &cts)
}

type CommentsTestSuite struct {
	suite.Suite
	dataDir string
	backend *backend
	token   string
	t       *testing.T
}

func (s *CommentsTestSuite) SetupTest() {
	require := s.Require()

	// setup backend
	s.backend = createBackend(s.t)
	require.NotNil(s.backend)

	u, id := createAndVerifyUser(s.t, s.backend)
	user, _ := s.backend.db.UserGet(u.Email)
	_, npr, err := createNewProposal(s.backend, s.t, user, id)
	require.NoError(err)

	s.token = npr.CensorshipRecord.Token
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

	testCases := make(map[string]commentTestCase)
	testCases["invalid comment length"] = commentTestCase{
		comment: www.NewComment{
			Token:    s.token,
			ParentID: "1",
			Comment:  generateRandomString(www.PolicyMaxCommentLength + 1),
		},
		userID: 1,
		expectedError: www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		},
	}
	testCases["valid comment length"] = commentTestCase{
		comment: www.NewComment{
			Token:    s.token,
			ParentID: "1",
			Comment:  "valid length",
		},
		userID:        1,
		expectedError: nil,
	}

	for testName, testCase := range testCases {
		reply, err := s.backend.addComment(testCase.comment, testCase.userID)
		require.EqualValuesf(testCase.expectedError, err, "failed test: %v",
			testName)
		if err == nil {
			require.NotNilf(reply, "failed test: %v", testName)
			require.NotZerof(reply.CommentID, "failed test: %v", testName)
		}
	}

}
