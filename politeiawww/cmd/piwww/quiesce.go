// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// QuiesceCmd toggles the quiesce mode
type QuiesceCmd struct{}

// Execute executes the quiesce command
func (cmd *QuiesceCmd) Execute(args []string) error {
	qr, err := client.Quiesce(&v2.Quiesce{})
	if err != nil {
		return err
	}
	return shared.PrintJSON(qr)
}

// QuiesceHelpMsg is the output of the help message when `policy` is specified
const quiesceHelpMsg = `quiesce

Toggle quiesce mode.

Arguments:
None

Response:
{
	"quiesce" (bool)    Indicates if in quiesce mode
}`
