package cockroachdb_test

import (
	"os"
	"testing"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/cockroachdb"

	"github.com/stretchr/testify/suite"
)

var (
	invalidEmail     = "invalidEmailFormat"
	unknownUserEmail = "unknown@decred.org"
	knownUser        = &database.User{
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
	*cockroachdb.DB
}

// SetupSuite creates and opens the cockroach db & guarantees that the
// users table is available
func (s *CockroachDBTestSuite) SetupSuite() {
	require := s.Require()
	dbhost := os.Getenv("CR_DBHOST")
	require.NotEmpty(dbhost)
	db, err := cockroachdb.New(dbhost)
	s.DB = db
	require.NoError(err)
	require.True(db.HasTable(&database.User{}))
	require.False(db.Shutdown)
}

// TearDownSuite closes the cockroach db
func (s *CockroachDBTestSuite) TearDownSuite() {
	require := s.Require()
	require.NoError(s.DB.Close())
}

// BeforeTest covers the steps executed before each test
func (s *CockroachDBTestSuite) SetupTest() {
	require := s.Require()

	// delete all the records for the user model
	require.NoError(s.DB.Delete(&database.User{}).Error)

	// add a known user - used for methods that require an existing user (ex: update)
	require.NoError(s.DB.Create(knownUser).Error)
}

func (s *CockroachDBTestSuite) TestUserNew() {
	require := s.Require()

	user := &database.User{
		Email: "test@decred.org",
	}

	testCases := []struct {
		user          *database.User
		expectedError error
	}{
		{
			&database.User{
				Email: invalidEmail,
			},
			database.ErrInvalidEmail,
		},
		{
			user,
			nil,
		},
		{
			user,
			database.ErrUserExists,
		},
	}

	for _, testCase := range testCases {
		err := s.DB.UserNew(testCase.user)
		require.EqualValues(testCase.expectedError, err)
		if err == nil {
			var dbUser database.User
			require.NoError(s.DB.Select("email = ?", testCase.user.Email).First(&dbUser).Error)
		}
	}
}

func (s *CockroachDBTestSuite) TestUserUpdate() {
	require := s.Require()

	// copy known user and modify a field to be used lates
	modifiedUser := *knownUser
	modifiedUser.Admin = true

	testCases := []struct {
		user          *database.User
		expectedError error
	}{
		{
			&database.User{
				Email: unknownUserEmail,
			},
			database.ErrUserNotFound,
		},
		{
			&modifiedUser,
			nil,
		},
	}

	for _, testCase := range testCases {
		err := s.DB.UserUpdate(testCase.user)
		require.Equal(testCase.expectedError, err)
		if err == nil {
			var dbUser database.User
			require.NoError(s.DB.First(&dbUser, modifiedUser.ID).Error)
			require.EqualValues(modifiedUser, dbUser)
		}
	}
}

func (s *CockroachDBTestSuite) TestUserGet() {
	require := s.Require()

	testCases := []struct {
		email         string
		expectedError error
	}{
		{
			unknownUserEmail,
			database.ErrUserNotFound,
		},
		{
			knownUser.Email,
			nil,
		},
	}

	for _, testCase := range testCases {
		user, err := s.DB.UserGet(testCase.email)
		require.EqualValues(testCase.expectedError, err)
		if err == nil {
			require.NotNil(user)
			require.EqualValues(knownUser, user)
		}
	}
}
