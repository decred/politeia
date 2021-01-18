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
	// Filenames of cached data saved to the plugin data dir. Brackets
	// are used to indicate a variable that should be replaced in the
	// filename.
	filenameSummary = "{tokenprefix}-summary.json"
)

// summaryCachePath accepts both full tokens and token prefixes, however it
// always uses the token prefix when generatig the path.
func (p *ticketVotePlugin) summaryCachePath(token string) (string, error) {
	// Use token prefix
	t, err := tokenDecodeAnyLength(token)
	if err != nil {
		return "", err
	}
	token = util.TokenPrefix(t)
	fn := strings.Replace(filenameSummary, "{tokenprefix}", token, 1)
	return filepath.Join(p.dataDir, fn), nil
}

var (
	errSummaryNotFound = errors.New("summary not found")
)

func (p *ticketVotePlugin) summaryCache(token string) (*ticketvote.VoteSummary, error) {
	p.Lock()
	defer p.Unlock()

	fp, err := p.summaryCachePath(token)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist
			return nil, errSummaryNotFound
		}
		return nil, err
	}

	var vs ticketvote.VoteSummary
	err = json.Unmarshal(b, &vs)
	if err != nil {
		return nil, err
	}

	return &vs, nil
}

func (p *ticketVotePlugin) summaryCacheSave(token string, vs ticketvote.VoteSummary) error {
	b, err := json.Marshal(vs)
	if err != nil {
		return err
	}

	p.Lock()
	defer p.Unlock()

	fp, err := p.summaryCachePath(token)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}

	log.Debugf("Saved votes summary: %v", token)

	return nil
}
