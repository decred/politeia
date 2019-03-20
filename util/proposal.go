// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"regexp"
	"strconv"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

var (
	validProposalName = regexp.MustCompile(CreateProposalNameRegex())
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

// CreateProposalNameRegex returns a regex string for matching the proposal name
func CreateProposalNameRegex() string {
	var validProposalNameBuffer bytes.Buffer
	validProposalNameBuffer.WriteString("^[")

	for _, supportedChar := range www.PolicyProposalNameSupportedChars {
		if len(supportedChar) > 1 {
			validProposalNameBuffer.WriteString(supportedChar)
		} else {
			validProposalNameBuffer.WriteString(`\` + supportedChar)
		}
	}
	validProposalNameBuffer.WriteString("]{")
	validProposalNameBuffer.WriteString(strconv.Itoa(www.PolicyMinProposalNameLength) + ",")
	validProposalNameBuffer.WriteString(strconv.Itoa(www.PolicyMaxProposalNameLength) + "}$")

	return validProposalNameBuffer.String()
}
