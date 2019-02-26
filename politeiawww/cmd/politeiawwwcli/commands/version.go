// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// VersionCmd retrieves server version information and CSRF token.
type VersionCmd struct{}

// Execute executes the version command.
func (cmd *VersionCmd) Execute(args []string) error {
	vr, err := client.Version()
	if err != nil {
		return err
	}
	return printJSON(vr)
}

// versionHelpMsg is the output of the help command when 'version' is
// specified.
const versionHelpMsg = `version

Fetch server version info and CSRF token.

Arguments: None

Result:
{
  "version":  (string)  Version of backend 
  "route":    (string)  Version route
  "pubkey":   (string)  Server public key
  "testnet":  (bool)    Whether of not testnet is being used
}`
