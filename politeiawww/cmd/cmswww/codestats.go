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
		UserID     string `positional-arg-name:"userid" optional:"true"`
		StartMonth uint   `positional-arg-name:"startmonth" optional:"true"`
		StartYear  uint   `positional-arg-name:"startyear" optional:"true"`
		EndMonth   uint   `positional-arg-name:"endmonth" optional:"true"`
		EndYear    uint   `positional-arg-name:"endyear" optional:"true"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cms user information command.
func (cmd *CodeStatsCmd) Execute(args []string) error {
	startDate := int64(0)
	endDate := int64(0)

	if cmd.Args.StartMonth != 0 {
		if cmd.Args.StartYear == 0 {
			return fmt.Errorf("most supply a start year if giving an start month")
		}
		startDate = time.Date(int(cmd.Args.StartYear), time.Month(cmd.Args.StartMonth), 0, 0, 0, 0, 0, time.UTC).Unix()
	} else {

	}
	if cmd.Args.EndMonth != 0 {
		if cmd.Args.EndYear == 0 {
			return fmt.Errorf("most supply a end year if giving an end month")
		}
		endDate = time.Date(int(cmd.Args.EndYear), time.Month(cmd.Args.EndMonth), 0, 0, 0, 0, 0, time.UTC).Unix()
	} else {
		fmt.Println("no end date provided, just getting the start date month")
		endDate = startDate
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
		UserID:    uid,
		StartTime: startDate,
		EndTime:   endDate,
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
