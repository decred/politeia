// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"net/http"

	pd "github.com/decred/politeia/politeiad/api/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/util"
)

func (p *politeiawww) quiesceToggle() {
	p.Lock()
	defer p.Unlock()
	p.quiesce = !p.quiesce
}

func (p *politeiawww) processQuiesce() (*www2.QuiesceReply, error) {
	// Toggle piwww quiesce mode
	p.quiesceToggle()

	// Toggle user db quiesce mode
	p.db.Quiesce()
	// Setup politeiad /quiesce request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	e := pd.Quiesce{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send politeiad request
	_, err = p.makeRequest(http.MethodGet, pd.QuiesceRoute, e)
	if err != nil {
		return nil, err
	}

	return &www2.QuiesceReply{
		Quiesce: p.quiesce,
	}, nil
}
