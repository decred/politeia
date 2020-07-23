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

func (p *politeiawww) setQuiesce(quiesce bool) {
	p.Lock()
	defer p.Unlock()
	p.quiesce = quiesce
}

func (p *politeiawww) processQuiesce(q www2.Quiesce) (*www2.QuiesceReply, error) {
	log.Tracef("processQuiesce: %v", q.Quiesce)

	// Setup politeiad /quiesce request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	e := pd.Quiesce{
		Challenge: hex.EncodeToString(challenge),
		Quiesce:   q.Quiesce,
	}

	// Send politeiad request
	_, err = p.makeRequest(http.MethodPost, pd.QuiesceRoute, e)
	if err != nil {
		return nil, err
	}

	// Toggle piwww quiesce mode
	p.setQuiesce(q.Quiesce)

	// Toggle user db quiesce mode
	p.db.SetQuiesce(q.Quiesce)

	return &www2.QuiesceReply{}, nil
}
