// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"
)

// cmdRFPTest runs tests to ensure the RFP workflow works as expected.
type cmdRFPTest struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdRFPTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdRFPTest) Execute(args []string) error {
	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// Verify admin login credentials
	admin := user{
		Email:    c.Args.AdminEmail,
		Password: c.Args.AdminPassword,
	}
	err := userLogin(admin)
	if err != nil {
		return fmt.Errorf("failed to login admin: %v", err)
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return fmt.Errorf("provided user is not an admin")
	}
	admin.Username = lr.Username

	// Verify paywall is disabled
	policyWWW, err := client.Policy()
	if err != nil {
		return err
	}
	if policyWWW.PaywallEnabled {
		return fmt.Errorf("paywall is not disabled")
	}

	// Log start time
	fmt.Printf("Start time: %v\n", timestampFromUnix(time.Now().Unix()))

	return nil
}

// RFPTestHelpMsg is the printed to stdout by the help command.
const RFPTestHelpMsg = `rfptest "adminemail" "adminpassword"

Run tests to ensure the RFP workflow works as expected..

Arguments:
1. adminemail     (string, required)  Email for admin account.
2. adminpassword  (string, required)  Password for admin account.
`
