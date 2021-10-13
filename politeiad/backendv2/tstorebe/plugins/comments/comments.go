// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"fmt"
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

	log.Infof("Starting comments fsck")

	counter := 0 // number of rebuilded record indexes

	// Navigate the provided record tokens and verify their record index
	// comments cache integrity. This will only rebuild the cache if any
	// inconsistency is found.
	for _, token := range tokens {

		// Get comment add digests for this record token.
		digestsAdd, err := p.tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorCommentAdd})
		if err != nil {
			return err
		}
		// Get comment del digests for this record token.
		digestsDel, err := p.tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorCommentDel})
		if err != nil {
			return err
		}
		// Get comment votes digests for this record token.
		digestsVote, err := p.tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorCommentVote})
		if err != nil {
			return err
		}

		// Create map to verify digests.
		addMap := make(map[string][]byte, len(digestsAdd))
		for _, d := range digestsAdd {
			addMap[hex.EncodeToString(d)] = d
		}
		delMap := make(map[string][]byte, len(digestsDel))
		for _, d := range digestsDel {
			delMap[hex.EncodeToString(d)] = d
		}
		voteMap := make(map[string][]byte, len(digestsVote))
		for _, d := range digestsVote {
			voteMap[hex.EncodeToString(d)] = d
		}

		// Get cached record index.
		state, err := p.tstore.RecordState(token)
		if err != nil {
			return err
		}
		cached, err := p.recordIndex(token, state)
		if err != nil {
			return err
		}

		// Verify that digests contained in the record index cache are valid.
		// Also, verify that all valid digests are contained in the record
		// index.
		var (
			bad          = false
			addsCounter  = 0
			delsCounter  = 0
			votesCounter = 0
		)
		for _, commentIndex := range cached.Comments {
			// Verify comment add digests.
			for _, add := range commentIndex.Adds {
				_, ok := addMap[hex.EncodeToString(add)]
				if !ok {
					bad = true
					break
				}
				addsCounter++
			}
			// Verify comment del digest, if it is set on the index.
			if len(commentIndex.Del) != 0 {
				digest := hex.EncodeToString(commentIndex.Del)
				_, ok := delMap[digest]
				if !ok {

					bad = true
					break
				}
				_, ok = addMap[digest]
				if ok {
					// This should not happen since the corresponding comment
					// add from a del entry should be deleted from the db.
					return fmt.Errorf("digest %v contained as a comment del"+
						"and comment add", digest)
				}
				delsCounter++
			}
			// Verify comment vote digests.
			for _, votes := range commentIndex.Votes {
				for _, vote := range votes {
					_, ok := voteMap[hex.EncodeToString(vote.Digest)]
					if !ok {
						bad = true
						break
					}
					votesCounter++
				}
			}
		}
		// Verify that all valid digests are contained on the record index.
		if addsCounter != len(digestsAdd) {
			bad = true
		}
		if delsCounter != len(digestsDel) {
			bad = true
		}
		if votesCounter != len(digestsVote) {
			bad = true
		}

		if !bad {
			// Cache verified successfully, continue to next token.
			continue
		}

		// Cache is inconsistent. Rebuild it with the digests retrieved
		// from tstore.

		// Initialize map for the comment indexes.
		index := make(map[uint32]*commentIndex)

		// Build comment adds.

		// Get comment add for the add digests.
		adds, err := p.commentAdds(token, digestsAdd)
		if err != nil {
			return err
		}
		// Initialize maps on the comment index for this record. Since all
		// votes need a corresponding add to be valid, it's ok to initialize
		// them by ranging the comment adds.
		for _, c := range adds {
			id := c.CommentID
			index[id] = &commentIndex{
				Adds:  make(map[uint32][]byte),
				Votes: make(map[string][]voteIndex),
			}
		}
		// Build the comment adds entry for the comment index.
		for k, c := range adds {
			id := c.CommentID
			version := c.Version
			index[id].Adds[version] = digestsAdd[k]
		}

		// Build comment dels.

		// Get comment dels for the del digest.
		dels, err := p.commentDels(token, digestsDel)
		if err != nil {
			return err
		}
		// Build the del entry for the comment index.
		for k, c := range dels {
			id := c.CommentID
			index[id].Del = digestsDel[k]
		}

		// Build comment votes.

		// Get comment votes for the vote digests
		votes, err := p.commentVotes(token, digestsVote)
		if err != nil {
			return err
		}
		// Build the Votes entry for the commentIndex.
		for k, v := range votes {
			userID := v.UserID
			commentID := v.CommentID
			index[commentID].Votes[userID] = append(
				index[commentID].Votes[userID], voteIndex{
					Vote:   v.Vote,
					Digest: digestsVote[k],
				})
		}

		// Remove current record index before saving new one.
		err = p.recordIndexRemove(token, state)
		if err != nil {
			return err
		}

		// Make record index with the comment indexes previously built.
		var ri recordIndex
		ri.Comments = make(map[uint32]commentIndex)
		for id, indx := range index {
			ri.Comments[id] = *indx
		}

		// Save record index cache.
		p.recordIndexSave(token, state, ri)

		counter++
	}

	log.Infof("%v records comments cache verified", len(tokens))
	log.Infof("%v records comments cache rebuilt", counter)

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
	}, nil
}
