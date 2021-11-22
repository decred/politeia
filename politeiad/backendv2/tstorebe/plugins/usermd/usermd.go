// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

var (
	_ plugins.PluginClient = (*usermdPlugin)(nil)
)

// usermdPlugin is the tstore backend implementation of the usermd plugin. The
// usermd plugin extends a record with user metadata.
//
// usermdPlugin satisfies the plugins PluginClient interface.
type usermdPlugin struct {
	sync.Mutex
	tstore plugins.TstoreClient

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Setup() error {
	log.Tracef("usermd Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Cmd: %x %v %v", token, cmd, payload)

	switch cmd {
	case usermd.CmdAuthor:
		return p.cmdAuthor(token)
	case usermd.CmdUserRecords:
		return p.cmdUserRecords(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("usermd Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeNewRecordPost:
		return p.hookNewRecordPost(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeEditMetadataPre:
		return p.hookEditMetadataPre(payload)
	case plugins.HookTypeSetRecordStatusPre:
		return p.hookSetRecordStatusPre(payload)
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

// Fsck performs a plugin file system check. The plugin is provided with the
// tokens for all records in the backend.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Fsck(tokens [][]byte) error {
	log.Tracef("usermd Fsck")

	// This map holds all fetched records
	rs := make(map[string]*backend.Record, len(tokens))

	// addMissingRecord adds the given record's token to a list of tokens sorted
	// by the latest status change timestamp, from newest to oldest.
	addMissingRecord := func(tokens []string, missingRecord *backend.Record) ([]string, error) {
		newTokens := make([]string, 0, len(tokens)+1)
		// Loop through tokens to find the record with a status change timestamp
		// older than the timestamp of the record being added.
		var (
			indexOlderRecord int
			r                *backend.Record
		)
		for i, t := range tokens {
			// Search in known records map
			r = rs[t]

			// Fetch record if not fetched yet
			if r == nil {
				// Decode string token
				b, err := hex.DecodeString(t)
				if err != nil {
					return nil, err
				}
				record, err := p.tstore.RecordPartial(b, 0, nil, false)
				if err != nil {
					return nil, err
				}

				// Add record to the known records map
				r = record
				rs[t] = r
			}

			// If current record's status change timestamp is older than
			// the timestamp of the record being added then the new record should
			// be added right before the current record.
			if r.RecordMetadata.Timestamp < missingRecord.RecordMetadata.Timestamp {
				indexOlderRecord = i
				break
			}
		}

		// Add records with status change timestamp newer than new record
		newTokens = append(newTokens, tokens[:indexOlderRecord]...)

		// Add new record
		newTokens = append(newTokens, missingRecord.RecordMetadata.Token)

		// Add record with status change timestamp older than new record
		newTokens = append(newTokens, tokens[indexOlderRecord:]...)

		fmt.Printf("oldTokens: %v, newTokens: %v, recordToken: %v \n\n\n\n\n",
			tokens, newTokens, missingRecord.RecordMetadata.Token)

		return newTokens, nil
	}

	for _, token := range tokens {
		// Check if record was already fetched
		tokenStr := hex.EncodeToString(token)
		r := rs[tokenStr]

		// Fetch record if not fetched yet
		if r == nil {
			record, err := p.tstore.RecordPartial(token, 0, nil, false)
			if err != nil {
				return err
			}

			// Add record to the known records map
			r = record
			rs[tokenStr] = r
		}

		// Decode user metadata
		um, err := userMetadataDecode(r.Metadata)
		if err != nil {
			return err
		}

		// Get the user cache for the record's author
		uc, err := p.userCache(um.UserID)
		if err != nil {
			return err
		}

		// Verify that the record is listed in the user cache under the
		// correct category.
		var found bool
		switch r.RecordMetadata.State {
		case backend.StateUnvetted:
			for _, t := range uc.Unvetted {
				if t == hex.EncodeToString(token) {
					found = true
				}
			}
			// Unvetted record is missing, add it
			if !found {
				uc.Unvetted, err = addMissingRecord(uc.Unvetted, r)
				if err != nil {
					return err
				}
			}

		case backend.StateVetted:
			for _, t := range uc.Vetted {
				if t == hex.EncodeToString(token) {
					found = true
				}
			}
			// Vetted record is missing, add it
			if !found {
				uc.Vetted, err = addMissingRecord(uc.Vetted, r)
				if err != nil {
					return err
				}
			}
		}

		// If a missing token was added to the user cache, save new user cache
		// to disk.
		if !found {
			p.Lock()
			err = p.userCacheSaveLocked(um.UserID, *uc)
			if err != nil {
				p.Unlock()
				return err
			}
			p.Unlock()
		}
	}

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Settings() []backend.PluginSetting {
	log.Tracef("usermd Settings")

	return nil
}

// New returns a new usermdPlugin.
func New(tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string) (*usermdPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, usermd.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &usermdPlugin{
		tstore:  tstore,
		dataDir: dataDir,
	}, nil
}
