// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// CMSUserInformationCmd requests a user's information.
type CMSUserInformationCmd struct {
	Args struct{}
}

// Execute executes the cms user information command.
func (cmd *CMSUserInformationCmd) Execute(args []string) error {

	uir, err := client.CMSUserInfomation()
	if err != nil {
		return err
	}

	// Print user information reply.
	return printJSON(uir)
}
