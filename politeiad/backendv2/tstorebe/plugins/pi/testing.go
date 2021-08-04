// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

// newTestPiPlugin returns a piPlugin that has been setup for testing.
func newTestPiPlugin(t *testing.T) *piPlugin {
	// Setup proposal name regex
	var (
		nameSupportedChars = pi.SettingProposalNameSupportedChars
		nameLengthMin      = pi.SettingProposalNameLengthMin
		nameLengthMax      = pi.SettingProposalNameLengthMax
	)
	rexp, err := util.Regexp(nameSupportedChars, uint64(nameLengthMin),
		uint64(nameLengthMax))
	if err != nil {
		t.Fatal(err)
	}

	// Encode the supported chars. This is done so that they can be
	// returned as a plugin setting string.
	b, err := json.Marshal(nameSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	nameSupportedCharsString := string(b)

	// Encode the proposal domains. This is done so that they can be
	// returned as a plugin setting string.
	domains := pi.SettingProposalDomains
	b, err = json.Marshal(domains)
	if err != nil {
		t.Fatal(err)
	}
	domainsString := string(b)

	// Translate domains slice to a Map[string]string.
	domainsMap := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		domainsMap[d] = struct{}{}
	}

	// Setup plugin context
	p := piPlugin{
		textFileSizeMax:            pi.SettingTextFileSizeMax,
		imageFileCountMax:          pi.SettingImageFileCountMax,
		imageFileSizeMax:           pi.SettingImageFileSizeMax,
		proposalNameLengthMin:      nameLengthMin,
		proposalNameLengthMax:      nameLengthMax,
		proposalNameSupportedChars: nameSupportedCharsString,
		proposalNameRegexp:         rexp,
		proposalAmountMin:          pi.SettingProposalAmountMin,
		proposalAmountMax:          pi.SettingProposalAmountMax,
		proposalStartDateMin:       pi.SettingProposalStartDateMin,
		proposalEndDateMax:         pi.SettingProposalEndDateMax,
		proposalDomainsEncoded:     domainsString,
		proposalDomains:            domainsMap,
	}

	return &p
}
