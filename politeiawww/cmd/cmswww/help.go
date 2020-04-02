// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// HelpCmd prints a detailed help message for the specified command.
type HelpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic"` // Topic to print help message for
	} `positional-args:"true"`
}

// Execute executes the help command.
func (cmd *HelpCmd) Execute(args []string) error {
	if cmd.Args.Topic == "" {
		return fmt.Errorf("Specify a command to print a detailed help " +
			"message for.  Example: cmswww help login")
	}

	switch cmd.Args.Topic {
	case "login":
		fmt.Printf("%s\n", shared.LoginHelpMsg)
	case "logout":
		fmt.Printf("%s\n", shared.LogoutHelpMsg)
	case "changepassword":
		fmt.Printf("%s\n", shared.ChangePasswordHelpMsg)
	case "changeusername":
		fmt.Printf("%s\n", shared.ChangeUsernameHelpMsg)
	case "newcomment":
		fmt.Printf("%s\n", shared.NewCommentHelpMsg)
	case "censorcomment":
		fmt.Printf("%s\n", shared.CensorCommentHelpMsg)
	case "manageuser":
		fmt.Printf("%s\n", cmsManageUserHelpMsg)
	case "version":
		fmt.Printf("%s\n", shared.VersionHelpMsg)
	case "me":
		fmt.Printf("%s\n", shared.MeHelpMsg)
	case "resetpassword":
		fmt.Printf("%s\n", shared.ResetPasswordHelpMsg)
	case "updateuserkey":
		fmt.Printf("%s\n", shared.UpdateUserKeyHelpMsg)
	case "users":
		fmt.Printf("%s\n", shared.UsersHelpMsg)
	case "userdetails":
		fmt.Printf("%s\n", userDetailsHelpMsg)
	case "policy":
		fmt.Printf("%s\n", policyHelpMsg)
	case "newinvoice":
		fmt.Printf("%s\n", newInvoiceHelpMsg)
	case "invoicedetails":
		fmt.Printf("%s\n", invoiceDetailsHelpMsg)
	case "editinvoice":
		fmt.Printf("%s\n", editInvoiceHelpMsg)
	case "setinvoicestatus":
		fmt.Printf("%s\n", setInvoiceStatusHelpMsg)
	case "invoicecomments":
		fmt.Printf("%s\n", invoiceCommentsHelpMsg)
	case "admininvoices":
		fmt.Printf("%s\n", adminInvoicesHelpMsg)
	case "userinvoices":
		fmt.Printf("%s\n", userInvoicesHelpMsg)
	case "invoiceexchangerate":
		fmt.Printf("%s\n", invoiceExchangeRateHelpMsg)
	case "dcccomments":
		fmt.Printf("%s\n", dccCommentsHelpMsg)
	case "newdcccomment":
		fmt.Printf("%s\n", newDCCCommentHelpMsg)

	default:
		fmt.Printf("invalid command: use 'cmswww -h' " +
			"to view a list of valid commands\n")
	}

	return nil
}
