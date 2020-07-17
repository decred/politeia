// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
)

func (p *politeiawww) toggleQiesce() (*www2.QiesceReply, error) {
	p.qiesce = !p.qiesce
	// XXX: toggle politeiad mode as well
	return &www2.QiesceReply{
		Qiesce: p.qiesce,
	}, nil
}
