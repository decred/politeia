// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"
	"time"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// LineItemPayoutsCmd request the line items that were paid out in the specified
// month/year.
type LineItemPayoutsCmd struct {
	Args struct {
		Month uint `positional-arg-name:"month"`
		Year  uint `positional-arg-name:"year"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the line item payouts command
func (cmd *LineItemPayoutsCmd) Execute(args []string) error {
	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	if cmd.Args.Month == 0 || cmd.Args.Year == 0 {
		return fmt.Errorf("month and year are both required to determine line item date range")
	}

	startDate := time.Date(int(cmd.Args.Year), time.Month(int(cmd.Args.Month)),
		0, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(int(cmd.Args.Year), time.Month(int(cmd.Args.Month+1)),
		0, 0, 0, 0, 0, time.UTC)

	lip := v1.LineItemPayouts{
		StartTime: startDate.Unix(),
		EndTime:   endDate.Unix(),
	}
	// Send request
	lipr, err := client.LineItemPayouts(&lip)
	if err != nil {
		return fmt.Errorf("error LineItemPayouts: %v", err)
	}

	// Print response details
	return printJSON(lipr)
}
