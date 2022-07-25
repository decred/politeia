// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdPolicy retrieves the API policy information.
type cmdPolicy struct{}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdPolicy) Execute(args []string) error {
	r, err := client.Policy()
	if err != nil {
		return err
	}
	log.Infof("%v", formatJSON(r))
	return nil
}
