// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
)

var (
	_ plugins.PluginClient = (*commentsPlugin)(nil)
)

// commentsPlugin is the tstore backend implementation of the comments plugin.
// The comments plugin extends a record with comment functionality.
//
// commentsPlugin satisfies the plugins PluginClient interface.
type commentsPlugin struct {
	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Plugin settings
	commentLengthMax uint32
	voteChangesMax   uint32
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Setup() error {
	log.Tracef("comments Setup")

	return nil
}

// Write executes a read/write plugin command. All operations are executed
// atomically by tstore when using this method. The plugin does not need to
// worry about concurrency issues.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Write(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("comments Write: %x %v %v", token, cmd, payload)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(tstore, token, payload)
	case comments.CmdEdit:
		return p.cmdEdit(tstore, token, payload)
	case comments.CmdDel:
		return p.cmdDel(tstore, token, payload)
	case comments.CmdVote:
		return p.cmdVote(tstore, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Read executes a read-only plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Read(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("comments Read: %x %v %v", token, cmd, payload)

	switch cmd {
	case comments.CmdGet:
		return p.cmdGet(tstore, token, payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(tstore, token)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(tstore, token, payload)
	case comments.CmdCount:
		return p.cmdCount(tstore, token)
	case comments.CmdVotes:
		return p.cmdVotes(tstore, token, payload)
	case comments.CmdTimestamps:
		return p.cmdTimestamps(tstore, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Hook(tstore plugins.TstoreClient, h plugins.HookT, payload string) error {
	log.Tracef("comments Hook: %x %v", plugins.Hooks[h])

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *commentsPlugin) Fsck() error {
	log.Tracef("comments Fsck")

	// Verify record index coherency
	// Verify CommentDel blobs were actually deleted

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
	}
}

// New returns a new comments plugin.
func New(settings []backend.PluginSetting, id *identity.FullIdentity) (*commentsPlugin, error) {
	// Default plugin settings
	var (
		commentLengthMax = comments.SettingCommentLengthMax
		voteChangesMax   = comments.SettingVoteChangesMax
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case comments.SettingKeyCommentLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			commentLengthMax = uint32(u)
		case comments.SettingKeyVoteChangesMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			voteChangesMax = uint32(u)
		default:
			return nil, fmt.Errorf("invalid comments plugin setting '%v'", v.Key)
		}
	}

	return &commentsPlugin{
		identity:         id,
		commentLengthMax: commentLengthMax,
		voteChangesMax:   voteChangesMax,
	}, nil
}
