// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
)

func (p *politeiawww) toggleQuiesce() (*www2.QuiesceReply, error) {
	p.quiesce = !p.quiesce
	// XXX: toggle politeiad mode as well
	return &www2.QuiesceReply{
		Quiesce: p.quiesce,
	}, nil
}
