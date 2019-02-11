// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// Help message displayed for the command 'politeiawwwcli help me'
var MeCmdHelpMsg = `me

Fetch details for the currently logged in user. 

Arguments:
None

Response:
{
  "isadmin":                 (bool)        Is user an admin
  "userid":                  (uuid.UUID)   Unique user uuid
  "email":                   (string)      Email address + lookup key
  "username":                (string)      Unique username
  "publickey":               (string)      User's public key
  "paywalladdress":          (string)      Registration paywall address
  "paywallamount":           (uint64)      Registration paywall amount in atoms
  "paywalltxnotbefore":      (int64)       Minimum timestamp for paywall tx
  "paywalltxid":             (string)      Paywall payment tx ID
  "proposalcredits":         (uint64)      Proposal credits available to spend
  "lastlogintime":           (int64)       Unix timestamp of last login date
  "sessionmaxage":           (int64)       Unix timestamp of session max age
}`

type MeCmd struct{}

func (cmd *MeCmd) Execute(args []string) error {
	lr, err := c.Me()
	if err != nil {
		return err
	}
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
