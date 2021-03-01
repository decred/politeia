// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

func newTestPiPlugin(t *testing.T) (*piPlugin, func()) {
	// Create plugin data directory
	dataDir, err := ioutil.TempDir("", pi.PluginID)
	if err != nil {
		t.Fatal(err)
	}

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

	// Setup plugin context
	p := piPlugin{
		dataDir:                    dataDir,
		textFileSizeMax:            pi.SettingTextFileSizeMax,
		imageFileCountMax:          pi.SettingImageFileCountMax,
		imageFileSizeMax:           pi.SettingImageFileSizeMax,
		proposalNameLengthMin:      nameLengthMin,
		proposalNameLengthMax:      nameLengthMax,
		proposalNameSupportedChars: nameSupportedCharsString,
		proposalNameRegexp:         rexp,
	}

	return &p, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
