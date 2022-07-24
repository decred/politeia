// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdVersion retrieves the server version information.
type cmdVersion struct{}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVersion) Execute(args []string) error {
	r, err := client.Version()
	if err != nil {
		return err
	}
	log.Infof("%v", formatJSON(r))
	return nil
}
