// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// CMSUserDetailsCmd requests a user's information.
type CMSUserDetailsCmd struct {
	Args struct{}
}

// Execute executes the cms user information command.
func (cmd *CMSUserDetailsCmd) Execute(args []string) error {
	lr, err := client.Me()
	if err != nil {
		return err
	}
	uir, err := client.CMSUserDetails(lr.UserID)
	if err != nil {
		return err
	}

	// Print user information reply.
	return printJSON(uir)
}
