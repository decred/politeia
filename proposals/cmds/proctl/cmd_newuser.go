// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdNewUser creates a new user.
type cmdNewUser struct {
	Args struct {
		Username string `positional-arg-name:"username"`
		Password string `positional-arg-name:"password"`
		Email    string `positional-arg-name:"email" optional:"true"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdNewUser) Execute(args []string) error {
	var (
		username = c.Args.Username
		password = c.Args.Password
		email    = c.Args.Email
	)
	_ = password
	_ = email

	log.Infof("New user %v created", username)

	return nil
}
