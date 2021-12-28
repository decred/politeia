// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/pkg/errors"
)

var (
	_ plugins.PluginClient = (*commentsPlugin)(nil)
)

// commentsPlugin is the tstore backend implementation of the comments plugin.
// The comments plugin extends a record with comment functionality.
//
// commentsPlugin satisfies the plugins PluginClient interface.
type commentsPlugin struct {
	sync.RWMutex
	tstore plugins.TstoreClient

	// dataDir is the comments plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Plugin settings
	commentLengthMax uint32
	voteChangesMax   uint32
	allowExtraData   bool
	votesPageSize    uint32
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Setup() error {
	log.Tracef("comments Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("comments Cmd: %x %v %v", token, cmd, payload)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(token, payload)
	case comments.CmdEdit:
		return p.cmdEdit(token, payload)
	case comments.CmdDel:
		return p.cmdDel(token, payload)
	case comments.CmdVote:
		return p.cmdVote(token, payload)
	case comments.CmdGet:
		return p.cmdGet(token, payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(token)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(token, payload)
	case comments.CmdCount:
		return p.cmdCount(token)
	case comments.CmdVotes:
		return p.cmdVotes(token, payload)
	case comments.CmdTimestamps:
		return p.cmdTimestamps(token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("comments Hook: %x %v", plugins.Hooks[h])

	return nil
}

// Fsck performs a plugin file system check. The plugin is provided with the
// tokens for all records in the backend.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Fsck(tokens [][]byte) error {
	log.Tracef("comments Fsck")

	log.Infof("Starting comments fsck for %v records", len(tokens))

	// Navigate the provided record tokens and verify their record index
	// comments cache integrity. This will only rebuild the cache if any
	// inconsistency is found.

	var counter int // number of record indexes rebuilt.

	for _, token := range tokens {
		// Verify the coherency of the record index.
		isCoherent, digests, err := p.verifyRecordIndex(token)
		if err != nil {
			return err
		}

		if isCoherent {
			continue
		}

		// The record index is not coherent and needs to be rebuilt.
		err = p.rebuildRecordIndex(token, *digests)
		if err != nil {
			return err
		}

		counter++
	}

	log.Infof("%v comment record indexes verified", len(tokens))
	log.Infof("%v comment record indexes rebuilt", counter)

	return nil
}

// Settings returns the plugin settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Settings() []backend.PluginSetting {
	log.Tracef("comments Settings")

	return []backend.PluginSetting{
		{
			Key:   comments.SettingKeyCommentLengthMax,
			Value: strconv.FormatUint(uint64(p.commentLengthMax), 10),
		},
		{
			Key:   comments.SettingKeyVoteChangesMax,
			Value: strconv.FormatUint(uint64(p.voteChangesMax), 10),
		},
		{
			Key:   comments.SettingKeyAllowExtraData,
			Value: strconv.FormatBool(p.allowExtraData),
		},
		{
			Key:   comments.SettingKeyVotesPageSize,
			Value: strconv.FormatUint(uint64(p.votesPageSize), 10),
		},
	}
}

// New returns a new comments plugin.
func New(tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity) (*commentsPlugin, error) {
	// Setup comments plugin data dir
	dataDir = filepath.Join(dataDir, comments.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Default plugin settings
	var (
		commentLengthMax = comments.SettingCommentLengthMax
		voteChangesMax   = comments.SettingVoteChangesMax
		allowExtraData   = comments.SettingAllowExtraData
		votesPageSize    = comments.SettingVotesPageSize
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case comments.SettingKeyCommentLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			commentLengthMax = uint32(u)
		case comments.SettingKeyVoteChangesMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			voteChangesMax = uint32(u)
		case comments.SettingKeyAllowExtraData:
			b, err := strconv.ParseBool(v.Value)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			allowExtraData = b
		case comments.SettingKeyVotesPageSize:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			votesPageSize = uint32(u)
		default:
			return nil, errors.Errorf("invalid comments plugin setting '%v'", v.Key)
		}
	}

	return &commentsPlugin{
		tstore:           tstore,
		identity:         id,
		dataDir:          dataDir,
		commentLengthMax: commentLengthMax,
		voteChangesMax:   voteChangesMax,
		allowExtraData:   allowExtraData,
		votesPageSize:    votesPageSize,
	}, nil
}
