// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// Help message displayed for the command 'politeiawwwcli help version'
var VersionCmdHelpMsg = `version

Fetch server info and CSRF token.

Arguments:
None

Result:
{
  "version":  (string)  Version of backend 
  "route":    (string)  Version route
  "pubkey":   (string)  Server public key
  "testnet":  (bool)    Whether of not testnet is being used
}`

type VersionCmd struct{}

func (cmd *VersionCmd) Execute(args []string) error {
	vr, err := c.Version()
	if err != nil {
		return err
	}
	return Print(vr, cfg.Verbose, cfg.RawJSON)
}
