// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// QiesceCmd toggles the qiesce mode
type QiesceCmd struct{}

// Execute executes the qiesce command
func (cmd *QiesceCmd) Execute(args []string) error {
	qr, err := client.Qiesce()
	if err != nil {
		return err
	}
	return shared.PrintJSON(qr)
}

// qiesceHelpMsg is the output of the help message when `policy` is specified
const qiesceHelpMsg = `qiesce

Toggle qiesce mode.

Arguments:
None

Response:
{
	"qiesce" (bool)    Indicates if in qiesce mode
}`
