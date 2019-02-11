// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// Help message displayed for the command 'politeiawwwcli help logout'
var LogoutCmdHelpMsg = `logout 

Logout as a user or admin.

Arguments:
None

Result:
{}`

type LogoutCmd struct{}

func (cmd *LogoutCmd) Execute(args []string) error {
	lr, err := c.Logout()
	if err != nil {
		return err
	}
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
