// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
)

const (
	// rfpTokensFilename is the filename of the file that contains the rfpTokens
	// structure.
	rfpTokensFilename = "rfp-tokens.json"
)

// rfpTokens contains the git backend tokens of all RFP parent proposals that
// were found during conversion from git backend types to tstore backend types.
//
// This structure is saved to disk during execution of the "convert" command
// and is read from disk during execution of the "import" command. The import
// command MUST add RFP parent proposals to tstore before the RFP submissions
// can be added since the submissions will need to reference the RFP parent
// tstore token.
type rfpTokens struct {
	Tokens []string
}

// saveRFPTokens saves the rfpTokens to disk.
func saveRFPTokens(legacyDir string, r rfpTokens) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	fp := rfpTokensPath(legacyDir)
	return ioutil.WriteFile(fp, b, filePermissions)
}

// loadRFPTokens loads the rfpTokens from disk.
func loadRFPTokens(legacyDir string) (*rfpTokens, error) {
	fp := rfpTokensPath(legacyDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var r rfpTokens
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// rfpTokensPath returns the full file path for the RFP tokens file.
func rfpTokensPath(legacyDir string) string {
	return filepath.Join(legacyDir, rfpTokensFilename)
}
