// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

var (
	_ plugins.PluginClient = (*ticketVotePlugin)(nil)
)

// ticketVotePlugin is the tstore backend implementation of the ticketvote
// plugin. The ticketvote plugin extends a record with dcr ticket voting
// functionality.
//
// ticketVotePlugin satisfies the plugins PluginClient interface.
type ticketVotePlugin struct {
	backend         backend.Backend
	tstore          plugins.TstoreClient
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

	// activeVotes is a memeory cache that contains data required to
	// validate vote ballots in a time efficient manner.
	activeVotes *activeVotes

	// Mutexes for on-disk caches
	mtxInv     sync.RWMutex // Vote inventory cache
	mtxSummary sync.Mutex   // Vote summaries cache
	mtxSubs    sync.Mutex   // Runoff vote submission cache

	// Plugin settings
	linkByPeriodMin int64  // In seconds
	linkByPeriodMax int64  // In seconds
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("ticketvote Setup")

	// Verify plugin dependencies
	var dcrdataFound bool
	for _, v := range p.backend.PluginInventory() {
		if v.ID == dcrdata.PluginID {
			dcrdataFound = true
		}
	}
	if !dcrdataFound {
		return fmt.Errorf("plugin dependency not registered: %v",
			dcrdata.PluginID)
	}

	// Update the inventory with the current best block. Retrieving
	// the inventory will cause it to update.
	log.Infof("Updating vote inventory")

	bestBlock, err := p.bestBlock()
	if err != nil {
		return fmt.Errorf("bestBlock: %v", err)
	}
	inv, err := p.Inventory(bestBlock)
	if err != nil {
		return fmt.Errorf("Inventory: %v", err)
	}

	// Build active votes cache
	log.Infof("Building active votes cache")

	started := make([]string, 0, len(inv.Entries))
	for _, v := range inv.Entries {
		if v.Status == ticketvote.VoteStatusStarted {
			started = append(started, v.Token)
		}
	}
	for _, v := range started {
		// Get the vote details
		token, err := tokenDecode(v)
		if err != nil {
			return err
		}

		reply, err := p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdDetails, "")
		if err != nil {
			return fmt.Errorf("PluginRead %x %v %v: %v",
				token, ticketvote.PluginID, ticketvote.CmdDetails, err)
		}
		var dr ticketvote.DetailsReply
		err = json.Unmarshal([]byte(reply), &dr)
		if err != nil {
			return err
		}
		if dr.Vote == nil {
			// Something is wrong. This should not happen.
			return fmt.Errorf("vote details not found for record in "+
				"started inventory %x", token)
		}

		// Add active votes entry
		p.activeVotesAdd(*dr.Vote)

		// Get cast votes
		reply, err = p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdResults, "")
		if err != nil {
			return fmt.Errorf("PluginRead %x %v %v: %v",
				token, ticketvote.PluginID, ticketvote.CmdResults, err)
		}
		var rr ticketvote.ResultsReply
		err = json.Unmarshal([]byte(reply), &rr)
		if err != nil {
			return err
		}
		for _, v := range rr.Votes {
			// Add cast vote to the active votes cache
			p.activeVotes.AddCastVote(v.Token, v.Ticket, v.VoteBit)
		}
	}

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("ticketvote Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(treeID, token, payload)
	case ticketvote.CmdStart:
		return p.cmdStart(treeID, token, payload)
	case ticketvote.CmdCastBallot:
		return p.cmdCastBallot(treeID, token, payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(treeID, token)
	case ticketvote.CmdResults:
		return p.cmdResults(treeID, token)
	case ticketvote.CmdSummary:
		return p.cmdSummary(treeID, token)
	case ticketvote.CmdSubmissions:
		return p.cmdSubmissions(token)
	case ticketvote.CmdInventory:
		return p.cmdInventory(payload)
	case ticketvote.CmdTimestamps:
		return p.cmdTimestamps(treeID, token, payload)

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
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v %x %v", plugins.Hooks[h], token, treeID)

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeSetRecordStatusPre:
		return p.hookSetRecordStatusPre(payload)
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(treeID, payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Fsck(treeIDs []int64) error {
	log.Tracef("ticketvote Fsck")

	// Verify all caches

	// Audit all finished votes
	//  - All votes that were cast were eligible
	//  - No duplicate votes
	/*
		finished := make([]string, 0, len(inv.Entries))
		for _, v := range inv.Entries {
			if v.Status == ticketvote.VoteStatusApproved ||
				v.Status == ticketvote.VoteStatusRejected {
				finished = append(finished, v.Token)
			}
		}
		for _, v := range finished {
			// Get all cast votes
			token, err := tokenDecode(v)
			if err != nil {
				return err
			}
			reply, err := p.backend.VettedPluginCmd(backend.PluginActionRead,
				token, ticketvote.PluginID, ticketvote.CmdResults, "")
			if err != nil {
				return err
			}
			var rr ticketvote.ResultsReply
			err = json.Unmarshal([]byte(reply), &rr)
			if err != nil {
				return err
			}

			// Verify that there are no duplicates
			tickets := make(map[string]struct{}, len(rr.Votes))
			for _, v := range rr.Votes {
				_, ok := tickets[v.Ticket]
				if ok {
					return fmt.Errorf("duplicate ticket found %v %v", v.Token, v.Ticket)
				}
				tickets[v.Ticket] = struct{}{}
			}
		}
	*/

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Settings() []backend.PluginSetting {
	log.Tracef("ticketvote Settings")

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

func New(backend backend.Backend, tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*ticketVotePlugin, error) {
	// Plugin settings
	var (
		linkByPeriodMin int64
		linkByPeriodMax int64
		voteDurationMin uint32
		voteDurationMax uint32
	)

	// Set plugin settings to defaults. These will be overwritten if
	// the setting was specified by the user.
	switch activeNetParams.Name {
	case chaincfg.MainNetParams().Name:
		linkByPeriodMin = ticketvote.SettingMainNetLinkByPeriodMin
		linkByPeriodMax = ticketvote.SettingMainNetLinkByPeriodMax
		voteDurationMin = ticketvote.SettingMainNetVoteDurationMin
		voteDurationMax = ticketvote.SettingMainNetVoteDurationMax
	case chaincfg.TestNet3Params().Name:
		linkByPeriodMin = ticketvote.SettingTestNetLinkByPeriodMin
		linkByPeriodMax = ticketvote.SettingTestNetLinkByPeriodMax
		voteDurationMin = ticketvote.SettingTestNetVoteDurationMin
		voteDurationMax = ticketvote.SettingTestNetVoteDurationMax
	case chaincfg.SimNetParams().Name:
		// Use testnet defaults for simnet
		linkByPeriodMin = ticketvote.SettingTestNetLinkByPeriodMin
		linkByPeriodMax = ticketvote.SettingTestNetLinkByPeriodMax
		voteDurationMin = ticketvote.SettingTestNetVoteDurationMin
		voteDurationMax = ticketvote.SettingTestNetVoteDurationMax
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
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyLinkByPeriodMin, linkByPeriodMin)

		case ticketvote.SettingKeyLinkByPeriodMax:
			i, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseInt(%v): %v",
					v.Key, v.Value, err)
			}
			linkByPeriodMax = i
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyLinkByPeriodMax, linkByPeriodMax)

		case ticketvote.SettingKeyVoteDurationMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMin = uint32(u)
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyVoteDurationMin, voteDurationMin)

		case ticketvote.SettingKeyVoteDurationMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMax = uint32(u)
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyVoteDurationMax, voteDurationMax)

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
		tstore:          tstore,
		dataDir:         dataDir,
		identity:        id,
		activeVotes:     newActiveVotes(),
		linkByPeriodMin: linkByPeriodMin,
		linkByPeriodMax: linkByPeriodMax,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
	}, nil
}
