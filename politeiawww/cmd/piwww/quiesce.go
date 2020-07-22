// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// QuiesceCmd sets the quiesce mode toggle value
type QuiesceCmd struct {
	Args struct {
		Quiesce bool `positional-arg-name:"quiesce"` // Quiesce mode toggle value
	} `positional-args:"true"`
}

// Execute executes the quiesce command
func (cmd *QuiesceCmd) Execute(args []string) error {
	quiesce := cmd.Args.Quiesce
	qr, err := client.Quiesce(&v2.Quiesce{
		Quiesce: quiesce,
	})
	if err != nil {
		return err
	}
	return shared.PrintJSON(qr)
}

// QuiesceHelpMsg is the output of the help message when `policy` is specified
const quiesceHelpMsg = `quiesce "quiesce"

Set quiesce mode state.

Arguments:
1. quiesce  (bool, required) Is quiesced

Flags:
None

Request:
{
	"quiesce"  (bool)  Quiesce mode toggle value
}

Response:
{
	"quiesce"  (bool)  Indicates if in quiesce mode
}`
