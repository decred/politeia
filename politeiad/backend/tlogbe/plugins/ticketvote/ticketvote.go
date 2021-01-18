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
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlogclient"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

var (
	_ plugins.Client = (*ticketVotePlugin)(nil)
)

// TODO verify all writes only accept full length tokens

// ticketVotePlugin satisfies the plugins.Client interface.
type ticketVotePlugin struct {
	sync.Mutex
	backend         backend.Backend
	tlog            tlogclient.Client
	activeNetParams *chaincfg.Params

	// dataDir is the ticket vote plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees. Ex, the vote summary once a
	// record vote has ended.
	dataDir string

	// Plugin settings
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks
	linkByPeriodMin int64  // In seconds
	linkByPeriodMax int64  // In seconds

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

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the plugins.Client interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("Setup")

	// Verify plugin dependencies
	var dcrdataFound bool
	for _, v := range p.backend.GetVettedPlugins() {
		if v.ID == dcrdata.ID {
			dcrdataFound = true
		}
	}
	if !dcrdataFound {
		return fmt.Errorf("plugin dependency not registered: %v", dcrdata.ID)
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
		reply, err := p.backend.VettedPluginCmd(token, ticketvote.ID,
			ticketvote.CmdResults, "")
		if err != nil {
			return fmt.Errorf("VettedPluginCmd %x %v %v: %v",
				token, ticketvote.ID, ticketvote.CmdResults, err)
		}
		var rr ticketvote.ResultsReply
		err = json.Unmarshal([]byte(reply), &rr)
		if err != nil {
			return err
		}
		for _, v := range rr.Votes {
			p.cachedVotesSet(v.Token, v.Ticket, v.VoteBit)
		}
	}

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.Client interface.
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

		// Internal plugin commands
	case cmdStartRunoffSub:
		return p.cmdStartRunoffSub(treeID, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.Client interface.
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
// This function satisfies the plugins.Client interface.
func (p *ticketVotePlugin) Fsck() error {
	log.Tracef("Fsck")

	return nil
}

/*
// linkByPeriodMin returns the minimum amount of time, in seconds, that the
// LinkBy period must be set to. This is determined by adding 1 week onto the
// minimum voting period so that RFP proposal submissions have at least one
// week to be submitted after the proposal vote ends.
func (p *politeiawww) linkByPeriodMin() int64 {
	var (
		submissionPeriod int64 = 604800 // One week in seconds
		blockTime        int64          // In seconds
	)
	switch {
	case p.cfg.TestNet:
		blockTime = int64(testNet3Params.TargetTimePerBlock.Seconds())
	case p.cfg.SimNet:
		blockTime = int64(simNetParams.TargetTimePerBlock.Seconds())
	default:
		blockTime = int64(mainNetParams.TargetTimePerBlock.Seconds())
	}
	return (int64(p.cfg.VoteDurationMin) * blockTime) + submissionPeriod
}

// linkByPeriodMax returns the maximum amount of time, in seconds, that the
// LinkBy period can be set to. 3 months is currently hard coded with no real
// reason for deciding on 3 months besides that it sounds like a sufficient
// amount of time.  This can be changed if there is a valid reason to.
func (p *politeiawww) linkByPeriodMax() int64 {
	return 7776000 // 3 months in seconds
}
*/

func New(backend backend.Backend, tlog tlogclient.Client, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*ticketVotePlugin, error) {
	// Plugin settings
	var (
		voteDurationMin uint32
		voteDurationMax uint32
	)

	// Set plugin settings to defaults. These will be overwritten if
	// the setting was specified by the user.
	switch activeNetParams.Name {
	case chaincfg.MainNetParams().Name:
		voteDurationMin = ticketvote.DefaultMainNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultMainNetVoteDurationMax
	case chaincfg.TestNet3Params().Name:
		voteDurationMin = ticketvote.DefaultTestNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultTestNetVoteDurationMax
	case chaincfg.SimNetParams().Name:
		voteDurationMin = ticketvote.DefaultSimNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultSimNetVoteDurationMax
	default:
		return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
	}

	// Parse user provided plugin settings
	for _, v := range settings {
		switch v.Key {
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
	dataDir = filepath.Join(dataDir, ticketvote.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &ticketVotePlugin{
		activeNetParams: activeNetParams,
		backend:         backend,
		tlog:            tlog,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
		dataDir:         dataDir,
		identity:        id,
		inv: inventory{
			unauthorized: make([]string, 0, 1024),
			authorized:   make([]string, 0, 1024),
			started:      make(map[string]uint32, 1024),
			finished:     make([]string, 0, 1024),
			bestBlock:    0,
		},
		votes:   make(map[string]map[string]string),
		mutexes: make(map[string]*sync.Mutex),
	}, nil
}
