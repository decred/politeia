// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/pi"
)

var (
	_ plugins.Client = (*piPlugin)(nil)
)

// piPlugin satisfies the plugins.Client interface.
type piPlugin struct {
	sync.Mutex
	backend backend.Backend

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string

	// Plugin settings
	indexFileName     string
	textFileCountMax  int
	textFileSizeMax   int // In bytes
	imageFileCountMax int
	imageFileSizeMax  int // In bytes

	proposalNameSupportedChars []string
	proposalNameLengthMin      int // In characters
	proposalNameLengthMax      int // In characters
	proposalNameRegexp         *regexp.Regexp
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Setup() error {
	log.Tracef("Setup")

	// TODO Verify vote and comment plugin dependency

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case pi.CmdVoteInv:
		return p.cmdVoteInv()
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v %x %v", treeID, token, plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypePluginPre:
		return p.hookPluginPre(treeID, token, payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("Fsck")

	return nil
}

func New(backend backend.Backend, settings []backend.PluginSetting, dataDir string) (*piPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, pi.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup proposal name regex
	// pregexp, err = regexp.Compile()
	var pregexp *regexp.Regexp

	return &piPlugin{
		dataDir: dataDir,
		backend: backend,
		// TODO pi plugin settings
		indexFileName:              "",
		textFileCountMax:           0,
		textFileSizeMax:            0,
		imageFileCountMax:          0,
		imageFileSizeMax:           0,
		proposalNameSupportedChars: []string{},
		proposalNameLengthMin:      0,
		proposalNameLengthMax:      0,
		proposalNameRegexp:         pregexp,
	}, nil
}
