// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// InvoicePayoutsCmd request the invoices that were paid out in the specified
// month/year.
type InvoicePayoutsCmd struct {
	Args struct {
		Month uint `positional-arg-name:"month"`
		Year  uint `positional-arg-name:"year"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the invoice payouts command
func (cmd *InvoicePayoutsCmd) Execute(args []string) error {
	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	if cmd.Args.Month == 0 || cmd.Args.Year == 0 {
		return fmt.Errorf("month and year are both required to determine invoice date range")
	}

	startDate := time.Date(int(cmd.Args.Year), time.Month(int(cmd.Args.Month)),
		0, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(int(cmd.Args.Year), time.Month(int(cmd.Args.Month+1)),
		0, 0, 0, 0, 0, time.UTC)

	lip := v1.InvoicePayouts{
		StartTime: startDate.Unix(),
		EndTime:   endDate.Unix(),
	}
	// Send request
	lipr, err := client.InvoicePayouts(&lip)
	if err != nil {
		return fmt.Errorf("error InvoicePayouts: %v", err)
	}

	// Print response details
	return shared.PrintJSON(lipr)
}
