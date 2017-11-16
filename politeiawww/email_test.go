package main

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// EmailTestSuite tests the logic concerning emails. Inherits the backend setup
// and teardown, as well as all the testify suite methods from BackendTestSuite
type EmailTestSuite struct {
	BackendTestSuite
}

func TestEmailTestSuite(t *testing.T) {
	suite.Run(t, new(EmailTestSuite))
}
