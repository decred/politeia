package main

import (
	"io/ioutil"
	"os"

	"github.com/stretchr/testify/suite"
)

const (
	dataDir = "test_politeiawww_backend"
)

// BackendTestSuite handles the backend setup and teardown
type BackendTestSuite struct {
	suite.Suite
	backend *backend
	dataDir string
}

// Alias suite.Run
var Run = suite.Run

// Overrides
func (s *BackendTestSuite) NoError(err error, msgAndArgs ...interface{}) {
	s.Require().NoError(err, msgAndArgs...)
}

func (s *BackendTestSuite) NotNil(object interface{}, msgAndArgs ...interface{}) {
	s.Require().NotNil(object, msgAndArgs...)
}

func (s *BackendTestSuite) Len(object interface{}, length int, msgAndArgs ...interface{}) {
	s.Require().Len(object, length, msgAndArgs...)
}

// SetupTest is responsible for setting up the data dir and the backend
func (s *BackendTestSuite) SetupTest() {
	// create data dir
	dir, err := ioutil.TempDir("", dataDir)
	s.NoError(err)
	s.NotNil(dir)
	s.dataDir = dir

	// setup backend
	backend, err := NewBackend(&config{DataDir: dir})
	s.NoError(err)
	s.NotNil(backend)
	backend.test = true
	s.backend = backend
}

// TearDownTest is responsible for closing the db & removing the data dir
func (s *BackendTestSuite) TearDownTest() {
	// close db
	s.NoError(s.backend.db.Close())

	// remove data dir
	s.NoError(os.RemoveAll(s.dataDir))
}
