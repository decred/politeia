// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// CMSUsersCmd retreives a list of users that have been filtered using the
// specified filtering params.
type CMSUsersCmd struct {
	Domain         int `long:"domain"`         // Domain filter
	ContractorType int `long:"contractortype"` // Contractor Type filter
}

// Execute executes the cmsusers command.
func (cmd *CMSUsersCmd) Execute(args []string) error {
	u := v1.CMSUsers{
		Domain:         v1.DomainTypeT(cmd.Domain),
		ContractorType: v1.ContractorTypeT(cmd.ContractorType),
	}

	ur, err := client.CMSUsers(&u)
	if err != nil {
		return err
	}
	return shared.PrintJSON(ur)
}

// CMSUsersHelpMsg is the output of the help command when 'cmsusers' is specified.
const CMSUsersHelpMsg = `cmsusers [flags]

Fetch a list of cms users based on filters provided.

Arguments: None

Flags:
  --domain            (int, optional)      Email filter
  --contractortype    (string, optional)   Username filter


Example (Admin):
cmsusers --domain=1 --contractortype=1

Result  :
{
  "users": [
    {
      "id":             (string)  User id
      "domain":         (string)  Domaint Type
      "username":       (string)  Username
      "contractortype": (string)  Contractor Type 
    }
  ]
}
`
