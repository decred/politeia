package cockroachdb_test

import (
	"os"
	"testing"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/cockroachdb"

	"github.com/stretchr/testify/suite"
)

var (
	invalidEmail = "invalidEmailFormat"
	knownUser    = &database.User{
		ID:             9999,
		Email:          "someone@decred.org",
		HashedPassword: []byte("password"),
		Admin:          false,
		NewUserVerificationToken:        []byte("something"),
		NewUserVerificationExpiry:       9999,
		ResetPasswordVerificationToken:  []byte("something"),
		ResetPasswordVerificationExpiry: 9999,
	}
)

func TestCockroachDBTestSuite(t *testing.T) {
	suite.Run(t, new(CockroachDBTestSuite))
}

type CockroachDBTestSuite struct {
	suite.Suite
	DB *cockroachdb.DB
}

// SetupSuite creates and opens the cockroach db & guarantees that the
// users table is available
func (s *CockroachDBTestSuite) SetupSuite() {
	require := s.Require()
	dbhost := os.Getenv("CR_DBHOST")
	require.NotEmpty(dbhost)
	DB, err := cockroachdb.New(dbhost)
	require.NoError(err)
	require.True(DB.HasTable(&database.User{}))
	require.False(DB.Shutdown)
}

// TearDownSuite closes the cockroach db
func (s *CockroachDBTestSuite) TearDownSuite() {
	require := s.Require()
	require.NoError(s.DB.Close())
}

// BeforeTest covers the steps executed before each test
func (s *CockroachDBTestSuite) BeforeTest() {
	require := s.Require()

	// delete all the records for the user model
	require.NoError(s.DB.Delete(&database.User{}).Error)

	// add a known user - used for methods that require an existing user (ex: update)
	require.NoError(s.DB.Create(knownUser).Error)
}

func (s *CockroachDBTestSuite) TestUserNew() {
	require := s.Require()

	testCases := []struct {
		context       string
		user          *database.User
		expectedError error
	}{
		{
			"invalid email format",
			&database.User{
				Email: invalidEmail,
			},
			database.ErrInvalidEmail,
		},
		{
			"user created",
			&database.User{},
			nil,
		},
		{
			"user exists",
			&database.User{},
			database.ErrUserExists,
		},
	}

	for _, testCase := range testCases {
		err := s.DB.UserNew(testCase.user)
		require.EqualValues(err, testCase.expectedError)
	}
}

func (s *CockroachDBTestSuite) TestUserUpdate() {
	require := s.Require()

	testCases := []struct {
		context       string
		user          *database.User
		expectedError error
	}{
		{
			"user not found",
			&database.User{
				Email: "invalidEmail",
			},
			database.ErrUserNotFound,
		},
		{
			"user updated",
			&database.User{},
			nil,
		},
	}

	for _, testCase := range testCases {
		err := s.DB.UserNew(testCase.user)
		require.EqualValues(err, testCase.expectedError)

	}
}

func (s *CockroachDBTestSuite) TestUserGet() {
	require := s.Require()

	testCases := []struct {
		context       string
		email         string
		expectedError error
	}{
		{
			"user not found",
			"unknown@decred.org",
			database.ErrUserNotFound,
		},
		{
			"return user",
			knownUser.Email,
			nil,
		},
	}

	for _, testCase := range testCases {
		user, err := s.DB.UserGet(testCase.email)
		require.EqualValues(err, testCase.expectedError)
		if err == nil {
			require.NotNil(user)
		}
	}
}
