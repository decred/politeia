// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

var (
	_ plugins.PluginClient = (*ticketVotePlugin)(nil)
)

// ticketVotePlugin satisfies the plugins.PluginClient interface.
type ticketVotePlugin struct {
	sync.Mutex
	backend         backend.Backend
	tlog            plugins.TlogClient
	activeNetParams *chaincfg.Params

	// dataDir is the ticket vote plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees. Ex, the vote summary once a
	// record vote has ended.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// inv contains the record inventory categorized by vote status.
	// The inventory will only contain public, non-abandoned records.
	// This cache is built on startup.
	inv inventory

	// votes contains the cast votes of ongoing record votes. This
	// cache is built on startup and record entries are removed once
	// the vote has ended and a vote summary has been cached.
	votes map[string]map[string]string // [token][ticket]voteBit

	// Mutexes contains a mutex for each record and are used to lock
	// the trillian tree for a given record to prevent concurrent
	// ticket vote plugin updates on the same tree. These mutexes are
	// lazy loaded and should only be used for tree updates, not for
	// cache updates.
	mutexes map[string]*sync.Mutex // [string]mutex

	// Plugin settings
	linkByPeriodMin int64  // In seconds
	linkByPeriodMax int64  // In seconds
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks
}

// mutex returns the mutex for the specified record.
func (p *ticketVotePlugin) mutex(token []byte) *sync.Mutex {
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
// This function satisfies the plugins.PluginClient interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("Setup")

	// Verify plugin dependencies
	var dcrdataFound bool
	for _, v := range p.backend.GetVettedPlugins() {
		if v.ID == dcrdata.PluginID {
			dcrdataFound = true
		}
	}
	if !dcrdataFound {
		return fmt.Errorf("plugin dependency not registered: %v",
			dcrdata.PluginID)
	}

	// Build inventory cache
	log.Infof("Building inventory cache")

	ibs, err := p.backend.InventoryByStatus()
	if err != nil {
		return fmt.Errorf("InventoryByStatus: %v", err)
	}

	bestBlock, err := p.bestBlock()
	if err != nil {
		return fmt.Errorf("bestBlock: %v", err)
	}

	var (
		unauthorized = make([]string, 0, 256)
		authorized   = make([]string, 0, 256)
		started      = make(map[string]uint32, 256) // [token]endHeight
		finished     = make([]string, 0, 256)
	)
	for _, tokens := range ibs.Vetted {
		for _, v := range tokens {
			token, err := tokenDecode(v)
			if err != nil {
				return err
			}
			s, err := p.summaryByToken(token)
			switch s.Status {
			case ticketvote.VoteStatusUnauthorized:
				unauthorized = append(unauthorized, v)
			case ticketvote.VoteStatusAuthorized:
				authorized = append(authorized, v)
			case ticketvote.VoteStatusStarted:
				started[v] = s.EndBlockHeight
			case ticketvote.VoteStatusFinished:
				finished = append(finished, v)
			default:
				return fmt.Errorf("invalid vote status %v %v", v, s.Status)
			}
		}
	}

	p.Lock()
	p.inv = inventory{
		unauthorized: unauthorized,
		authorized:   authorized,
		started:      started,
		finished:     finished,
		bestBlock:    bestBlock,
	}
	p.Unlock()

	// Build votes cache
	log.Infof("Building votes cache")

	for k := range started {
		token, err := tokenDecode(k)
		if err != nil {
			return err
		}
		reply, err := p.backend.VettedPluginCmd(token, ticketvote.PluginID,
			ticketvote.CmdResults, "")
		if err != nil {
			return fmt.Errorf("VettedPluginCmd %x %v %v: %v",
				token, ticketvote.PluginID, ticketvote.CmdResults, err)
		}
		var rr ticketvote.ResultsReply
		err = json.Unmarshal([]byte(reply), &rr)
		if err != nil {
			return err
		}
		for _, v := range rr.Votes {
			p.votesCacheSet(v.Token, v.Ticket, v.VoteBit)
		}
	}

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.PluginClient interface.
func (p *ticketVotePlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %x %v", treeID, token, cmd)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(treeID, token, payload)
	case ticketvote.CmdStart:
		return p.cmdStart(treeID, token, payload)
	case ticketvote.CmdCastBallot:
		return p.cmdCastBallot(treeID, token, payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(treeID, token, payload)
	case ticketvote.CmdResults:
		return p.cmdResults(treeID, token, payload)
	case ticketvote.CmdSummary:
		return p.cmdSummary(treeID, token, payload)
	case ticketvote.CmdInventory:
		return p.cmdInventory()
	case ticketvote.CmdTimestamps:
		return p.cmdTimestamps(treeID, token, payload)
	case ticketvote.CmdLinkedFrom:
		return p.cmdLinkedFrom(token)

		// Internal plugin commands
	case cmdStartRunoffSubmission:
		return p.cmdStartRunoffSubmission(treeID, token, payload)
	case cmdRunoffDetails:
		return p.cmdRunoffDetails(treeID)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.PluginClient interface.
func (p *ticketVotePlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v %x %v", treeID, token, plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.PluginClient interface.
func (p *ticketVotePlugin) Fsck(treeIDs []int64) error {
	log.Tracef("Fsck")

	// Verify all caches

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins.PluginClient interface.
func (p *ticketVotePlugin) Settings() []backend.PluginSetting {
	log.Tracef("Settings")

	return []backend.PluginSetting{
		{
			Key:   ticketvote.SettingKeyLinkByPeriodMin,
			Value: strconv.FormatInt(p.linkByPeriodMin, 10),
		},
		{
			Key:   ticketvote.SettingKeyLinkByPeriodMax,
			Value: strconv.FormatInt(p.linkByPeriodMax, 10),
		},
		{
			Key:   ticketvote.SettingKeyVoteDurationMin,
			Value: strconv.FormatUint(uint64(p.voteDurationMin), 10),
		},
		{
			Key:   ticketvote.SettingKeyVoteDurationMax,
			Value: strconv.FormatUint(uint64(p.voteDurationMax), 10),
		},
	}
}

func New(backend backend.Backend, tlog plugins.TlogClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*ticketVotePlugin, error) {
	// Plugin settings
	var (
		linkByPeriodMin = ticketvote.SettingLinkByPeriodMin
		linkByPeriodMax = ticketvote.SettingLinkByPeriodMax
		voteDurationMin uint32
		voteDurationMax uint32
	)

	// Set plugin settings to defaults. These will be overwritten if
	// the setting was specified by the user.
	switch activeNetParams.Name {
	case chaincfg.MainNetParams().Name:
		voteDurationMin = ticketvote.SettingMainNetVoteDurationMin
		voteDurationMax = ticketvote.SettingMainNetVoteDurationMax
	case chaincfg.TestNet3Params().Name:
		voteDurationMin = ticketvote.SettingTestNetVoteDurationMin
		voteDurationMax = ticketvote.SettingTestNetVoteDurationMax
	case chaincfg.SimNetParams().Name:
		voteDurationMin = ticketvote.SettingSimNetVoteDurationMin
		voteDurationMax = ticketvote.SettingSimNetVoteDurationMax
	default:
		return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
	}

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case ticketvote.SettingKeyLinkByPeriodMin:
			i, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseInt(%v): %v",
					v.Key, v.Value, err)
			}
			linkByPeriodMin = i
		case ticketvote.SettingKeyLinkByPeriodMax:
			i, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseInt(%v): %v",
					v.Key, v.Value, err)
			}
			linkByPeriodMax = i
		case ticketvote.SettingKeyVoteDurationMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMin = uint32(u)
		case ticketvote.SettingKeyVoteDurationMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMax = uint32(u)
		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Create the plugin data directory
	dataDir = filepath.Join(dataDir, ticketvote.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &ticketVotePlugin{
		activeNetParams: activeNetParams,
		backend:         backend,
		tlog:            tlog,
		dataDir:         dataDir,
		identity:        id,
		inv: inventory{
			unauthorized: make([]string, 0, 1024),
			authorized:   make([]string, 0, 1024),
			started:      make(map[string]uint32, 1024),
			finished:     make([]string, 0, 1024),
			bestBlock:    0,
		},
		votes:           make(map[string]map[string]string),
		mutexes:         make(map[string]*sync.Mutex),
		linkByPeriodMin: linkByPeriodMin,
		linkByPeriodMax: linkByPeriodMax,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
	}, nil
}
