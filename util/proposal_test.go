package util_test

import (
	"encoding/base64"
	"github.com/decred/politeia/util"
	"math/rand"
	"testing"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func TestGetProposalName(t *testing.T) {
	testCases := []struct {
		input         string
		output        string
		expectedError error
	}{
		{
			base64.StdEncoding.EncodeToString([]byte("this is-the-title")),
			"this is-the-title",
			nil,
		},
		{
			base64.StdEncoding.EncodeToString([]byte("this-is-the title\nbody")),
			"this-is-the title",
			nil,
		},
		// payload does not have a title
		{
			base64.StdEncoding.EncodeToString([]byte("\n\nbody")),
			"",
			nil,
		},
	}

	// test
	for _, testCase := range testCases {
		result, err := util.GetProposalName(testCase.input)
		if err != testCase.expectedError {
			t.Errorf("Expected %v, got %v.", testCase.expectedError, err)
		}
		if err == nil {
			if result != testCase.output {
				t.Errorf("Expected %s, got %s.", testCase.output, result)
			}
		}
	}
}

func TestIsValidProposalName(t *testing.T) {
	testCases := []struct {
		input  string // @rgeraldes - valid input is a string without new lines
		output bool
	}{
		// empty test
		{
			generateRandomString(0),
			false,
		},
		// 7 characters
		{
			generateRandomString(7),
			false,
		},

		// 81 characters
		{
			generateRandomString(81),
			false,
		},
		// 8 characters
		{
			"12345678",
			true,
		},
		{
			"valid title",
			true,
		},
		{
			" - title: is valid; title. !.,  ",
			true,
		},
		{
			" - title: is valid; title.   ",
			true,
		},
		{
			"\n\n#This-is MY tittle###",
			false,
		},
		{
			"{this-is-the-title}",
			false,
		},
		{
			"\t<this- is-the title>",
			false,
		},
		{
			"{this   -is-the-title}   ",
			false,
		},
		{
			"###this is the title***",
			false,
		},
		{
			"###this is the title@+",
			true,
		},
	}

	for _, testCase := range testCases {
		if result := util.IsValidProposalName(testCase.input); result != testCase.output {
			t.Errorf("Expected %t, got %t.", testCase.output, result)
		}
	}
}
