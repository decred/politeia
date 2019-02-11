// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

type SecretCmd struct{}

func (cmd *SecretCmd) Execute(args []string) error {
	ue, err := c.Secret()
	if err != nil {
		return err
	}
	return Print(ue, cfg.Verbose, cfg.RawJSON)
}
