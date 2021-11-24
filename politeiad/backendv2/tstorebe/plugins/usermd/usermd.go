// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
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

// addMissingRecord adds the given record's token to a list of tokens sorted
// by the latest status change timestamp, from newest to oldest.
func (p *usermdPlugin) addMissingRecord(tokens []string, missingRecord *backend.Record) ([]string, error) {
	// Make list of records to be able to sort by latest status change
	// timestamp.
	records := make([]*backend.Record, 0, len(tokens)+1)
	for _, t := range tokens {
		// Decode string token
		b, err := hex.DecodeString(t)
		if err != nil {
			return nil, err
		}
		r, err := p.tstore.RecordPartial(b, 0, nil, false)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	// Append new record then sort reocrds by latest status change timestamp
	// from newest to oldest.
	records = append(records, missingRecord)

	// Sort records
	sort.Slice(records, func(i, j int) bool {
		return records[i].RecordMetadata.Timestamp >
			records[j].RecordMetadata.Timestamp
	})

	// Return sorted tokens
	newTokens := make([]string, 0, len(records))
	for _, record := range records {
		newTokens = append(newTokens, record.RecordMetadata.Token)
	}

	return newTokens, nil
}

// Fsck performs a plugin file system check. The plugin is provided with the
// tokens for all records in the backend.
//
// It verifies the user cache using the following process:
//
// 1. For each record, get the user metadata file from the db.
// 2. Get the user cache for the record's author.
// 3. Verify that the record is listed in the user cache under the
//    correct category.  If the record is not found in the user
//    cache, add it.  The tokens listed in the user cache are
//    ordered by the timestamp of their most recent status change
//    from newest to oldest.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Fsck(tokens [][]byte) error {
	log.Tracef("usermd Fsck")

	// Number of records which were added to the user cache.
	var c int64

	for _, token := range tokens {
		tokenStr := hex.EncodeToString(token)
		r, err := p.tstore.RecordPartial(token, 0, nil, false)
		if err != nil {
			return err
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
				if t == tokenStr {
					found = true
				}
			}
			// Unvetted record is missing, add it
			if !found {
				uc.Unvetted, err = p.addMissingRecord(uc.Unvetted, r)
				if err != nil {
					return err
				}
			}

		case backend.StateVetted:
			for _, t := range uc.Vetted {
				if t == tokenStr {
					found = true
				}
			}
			// Vetted record is missing, add it
			if !found {
				uc.Vetted, err = p.addMissingRecord(uc.Vetted, r)
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
			c++
			log.Debugf("missing %v record %v was added to %v user records cache",
				backend.States[r.RecordMetadata.State], tokenStr, um.UserID)
		}
	}

	log.Infof("%v missing records were added to the user records cache", c)

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
