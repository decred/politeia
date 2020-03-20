// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// CodeStatsCmd requests a user's information.
type CodeStatsCmd struct {
	Args struct {
		Month  uint   `positional-arg-name:"month" optional:"true"`
		Year   uint   `positional-arg-name:"year" optional:"true"`
		UserID string `positional-arg-name:"userid" optional:"true"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cms user information command.
func (cmd *CodeStatsCmd) Execute(args []string) error {
	month := cmd.Args.Month
	year := cmd.Args.Year

	if month == 0 || year == 0 {
		if time.Now().Month() == 1 {
			month = 12
			year = uint(time.Now().Year()) - 1
		} else {
			month = uint(time.Now().Month()) - 1
			year = uint(time.Now().Year())
		}
		fmt.Printf("month/year not provided requesting current %v/%v\n", month, year)
	}
	uid := cmd.Args.UserID

	if uid == "" {
		lr, err := client.Me()
		if err != nil {
			return err
		}
		uid = lr.UserID
	}

	ucs := cms.UserCodeStats{
		UserID: uid,
		Month:  int64(month),
		Year:   int64(year),
	}

	csr, err := client.CodeStats(ucs)
	if err != nil {
		return err
	}

	// Print user information reply.
	return shared.PrintJSON(csr)
}

// codeStatsDetailsHelpMsg is the output of the help command when 'userdetails' is
// specified.
const codeStatsDetailsHelpMsg = `codestats "userid" 

Fetch code stats by user id. 

Arguments:
1. userid      (string, required)   User id 
`
