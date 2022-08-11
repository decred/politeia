// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmds contains the list of CLI commands.
type cmds struct {
	// The config is parsed separately from the commands and set as a global
	// variable. The DoNotUse config field is here as a workaround to prevent
	// go-flags unknown flag errors during parsing and to allow the config fields
	// to be printed in the go-flags created help message. It should not be used
	// by the commands.
	DoNotUse *config

	Version     cmdVersion     `command:"version"`
	Policy      cmdPolicy      `command:"policy"`
	NewUser     cmdNewUser     `command:"newuser"`
	Login       cmdLogin       `command:"login"`
	Logout      cmdLogout      `command:"logout"`
	UpdateGroup cmdUpdateGroup `command:"updategroup"`
	Me          cmdMe          `command:"me"`
}
