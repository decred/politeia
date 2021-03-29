// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

const (
	// filenameSummary is the file name of the vote summary for a
	// record. These summaries are cached in the plugin data dir.
	filenameSummary = "{shorttoken}-summary.json"
)

// summaryCachePath accepts both full tokens and token prefixes, however it
// always uses the token prefix when generatig the path.
func (p *ticketVotePlugin) summaryCachePath(token string) (string, error) {
	// Use token prefix
	stoken, err := util.ShortTokenString(token)
	if err != nil {
		return "", err
	}
	fn := strings.Replace(filenameSummary, "{shorttoken}", stoken, 1)
	return filepath.Join(p.dataDir, fn), nil
}

var (
	// errSummaryNotFound is returned when a cached summary is not
	// found for a record.
	errSummaryNotFound = errors.New("summary not found")
)

// summaryCache returns the cached vote summary for a record.
//
// This function must be called WITHOUT the mtxSummary lock held.
func (p *ticketVotePlugin) summaryCache(token string) (*ticketvote.SummaryReply, error) {
	fp, err := p.summaryCachePath(token)
	if err != nil {
		return nil, err
	}

	p.mtxSummary.Lock()
	defer p.mtxSummary.Unlock()

	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist
			return nil, errSummaryNotFound
		}
		return nil, err
	}

	var sr ticketvote.SummaryReply
	err = json.Unmarshal(b, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// summaryCacheSave saves a vote summary to the cache for a record.
//
// This function must be called WITHOUT the mtxSummary lock held.
func (p *ticketVotePlugin) summaryCacheSave(token string, sr ticketvote.SummaryReply) error {
	b, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	fp, err := p.summaryCachePath(token)
	if err != nil {
		return err
	}

	p.mtxSummary.Lock()
	defer p.mtxSummary.Unlock()

	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}

	log.Debugf("Saved votes summary: %v", token)

	return nil
}
