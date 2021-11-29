// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

// newTestPiPlugin returns a piPlugin that has been setup for testing.
func newTestPiPlugin(t *testing.T) (*piPlugin, func()) {
	// Create plugin data directory
	dataDir, err := ioutil.TempDir("", pi.PluginID)
	if err != nil {
		t.Fatal(err)
	}

	// Setup title regex
	var (
		titleSupportedChars = pi.SettingTitleSupportedChars
		titleLengthMin      = pi.SettingTitleLengthMin
		titleLengthMax      = pi.SettingTitleLengthMax
	)
	rexp, err := util.Regexp(titleSupportedChars, uint64(titleLengthMin),
		uint64(titleLengthMax))
	if err != nil {
		t.Fatal(err)
	}

	// Encode the supported chars. This is done so that they can be
	// returned as a plugin setting string.
	b, err := json.Marshal(titleSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	titleSupportedCharsString := string(b)

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
		dataDir:                 dataDir,
		textFileSizeMax:         pi.SettingTextFileSizeMax,
		imageFileCountMax:       pi.SettingImageFileCountMax,
		imageFileSizeMax:        pi.SettingImageFileSizeMax,
		titleLengthMin:          titleLengthMin,
		titleLengthMax:          titleLengthMax,
		titleSupportedChars:     titleSupportedCharsString,
		titleRegexp:             rexp,
		proposalAmountMin:       pi.SettingProposalAmountMin,
		proposalAmountMax:       pi.SettingProposalAmountMax,
		proposalStartDateMin:    pi.SettingProposalStartDateMin,
		proposalEndDateMax:      pi.SettingProposalEndDateMax,
		proposalDomainsEncoded:  domainsString,
		proposalDomains:         domainsMap,
		billingStatusChangesMax: pi.SettingBillingStatusChangesMax,
		statuses: proposalStatuses{
			data:    make(map[string]*statusEntry, statusesLimit),
			entries: list.New(),
		},
	}

	return &p, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
