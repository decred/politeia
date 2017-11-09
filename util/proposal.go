package util

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"regexp"

	www "github.com/decred/politeia/politeiawww/api/v1"
)

var (
	validProposalName = regexp.MustCompile(www.ValidProposalNameRegExp)
)

// ProposalName returns a proposal name
func GetProposalName(payload string) (string, error) {
	// decode payload (base64)
	rawPayload, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", err
	}
	// @rgeraldes - used reader instead of scanner
	// due to the size of the input (scanner > token too long)
	// get the first line from the payload
	reader := bufio.NewReader(bytes.NewReader(rawPayload))
	proposalName, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}

	return string(proposalName), nil
}

// IsValidProposalName reports whether str is a valid proposal name
func IsValidProposalName(str string) bool {
	return validProposalName.MatchString(str)
}
