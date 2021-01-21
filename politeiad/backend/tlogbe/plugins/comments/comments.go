// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
)

// TODO prevent duplicate comments
// TODO upvoting a comment twice in the same second causes a duplicate leaf
// error which causes a 500. Solution: add the timestamp to the vote index.

var (
	_ plugins.Client = (*commentsPlugin)(nil)
)

// commentsPlugin is the tlog backend implementation of the comments plugin.
//
// commentsPlugin satisfies the plugins.Client interface.
type commentsPlugin struct {
	sync.Mutex
	tlog plugins.TlogClient

	// dataDir is the comments plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Mutexes contains a mutex for each record. The mutexes are lazy
	// loaded.
	mutexes map[string]*sync.Mutex // [string]mutex
}

// mutex returns the mutex for a record.
func (p *commentsPlugin) mutex(token []byte) *sync.Mutex {
	p.Lock()
	defer p.Unlock()

	t := hex.EncodeToString(token)
	m, ok := p.mutexes[t]
	if !ok {
		// Mutexes is lazy loaded
		m = &sync.Mutex{}
		p.mutexes[t] = m
	}

	return m
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Setup() error {
	log.Tracef("Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %x %v", treeID, token, cmd)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(treeID, token, payload)
	case comments.CmdEdit:
		return p.cmdEdit(treeID, token, payload)
	case comments.CmdDel:
		return p.cmdDel(treeID, token, payload)
	case comments.CmdVote:
		return p.cmdVote(treeID, token, payload)
	case comments.CmdGet:
		return p.cmdGet(treeID, token, payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(treeID, token, payload)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(treeID, token, payload)
	case comments.CmdCount:
		return p.cmdCount(treeID, token, payload)
	case comments.CmdVotes:
		return p.cmdVotes(treeID, token, payload)
	case comments.CmdTimestamps:
		return p.cmdTimestamps(treeID, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v %x %v", treeID, token, plugins.Hooks[h])

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("Fsck")

	// Verify CommentDel blobs were actually deleted

	return nil
}

// New returns a new comments plugin.
func New(tlog plugins.TlogClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity) (*commentsPlugin, error) {
	// Setup comments plugin data dir
	dataDir = filepath.Join(dataDir, comments.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &commentsPlugin{
		tlog:     tlog,
		identity: id,
		dataDir:  dataDir,
		mutexes:  make(map[string]*sync.Mutex),
	}, nil
}
