// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// UserDetailsCmd gets the user details for the specified user.
type UserDetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user details command.
func (cmd *UserDetailsCmd) Execute(args []string) error {
	udr, err := client.UserDetails(cmd.Args.UserID)
	if err != nil {
		return err
	}
	return shared.PrintJSON(udr)
}

// userDetailsHelpMsg is the output of the help command when 'userdetails' is
// specified.
const userDetailsHelpMsg = `userdetails "userid" 

Fetch user details by user id. 

Arguments:
1. userid      (string, required)   User id 

Result:
{
  "user": {
    "id":                                (uuid.UUID) Unique user uuid
    "email":                             (string)    Email address + lookup key
    "username":                          (string)    Unique username
    "isadmin":                           (bool)      Is user an admin
    "newuserpaywalladdress":             (string)    Address for paywall payment
    "newuserpaywallamount":              (uint64)    Paywall amount
    "newuserpaywalltx":                  (string)    Paywall transaction id
    "newuserpaywalltxnotbefore":         (int64)     Txs before this time are not valid
    "newuserpaywallpollexpiry":          (int64)     Time to stop polling paywall address
    "newuserverificationtoken":          ([]byte)    Registration verification token
    "newuserverificationexpiry":         (int64)     Registration verification expiration
    "updatekeyverificationtoken":        ([]byte)    Keypair update verification token 
    "updatekeyverificationexpiry":       (int64)     Verification expiration
    "resetpasswordverificationtoken":    ([]byte)    Reset password token
    "resetpasswordverificationexpiry":   (int64)     Reset password token expiration
    "lastlogintime":                     (int64)     Unix timestamp of last user login 
    "failedloginattempts":               (uint64)    Number of sequential failed login attempts
    "isdeactivated":                     (bool)      Whether the account is deactivated or not
    "islocked":                          (bool)      Whether the account is locked or not
    "identities": [
      {
        "pubkey":                        (string)    User's public key
        "isactive":                      (bool)      Whether user's identity is active or not 
      }
    ],
    "proposalcredits":                   (uint64)    Number of available proposal credits
    "emailnotifications":                (uint64)    Whether to notify via emails
  }
}`
