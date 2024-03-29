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

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
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

	// inv provides an API for managing the cached vote inventory. The
	// data is cached in the tstore provided plugin cache.
	inv *invClient

	// summaries provides an API for interacting with the vote summaries
	// cache. The data is saved to the tstore provided plugin cache.
	summaries *summariesClient

	// subs provides an API for interacting with the runoff vote submissions
	// cache. The data is saved to the tstore provided plugin cache.
	subs *subsClient

	// Plugin settings
	linkByPeriodMin    int64  // In seconds
	linkByPeriodMax    int64  // In seconds
	voteDurationMin    uint32 // In blocks
	voteDurationMax    uint32 // In blocks
	summariesPageSize  uint32
	inventoryPageSize  uint32
	timestampsPageSize uint32
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
		return errors.Errorf("%v plugin dependency not registered",
			dcrdata.PluginID)
	}

	// Build the active votes cache
	log.Infof("Building active votes cache")

	var (
		// started is populated with the tokens of all records
		// that have a vote status of VoteStatusStarted.
		started = make([]string, 0, 256)

		page uint32 = 1
	)
	bestBlock, err := p.bestBlock()
	if err != nil {
		return err
	}
	for {
		entries, err := p.inv.GetPageForStatus(bestBlock,
			ticketvote.VoteStatusStarted, page)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			// We've reached the end of the inventory
			// for the VoteStatusStarted entries.
			break
		}
		started = append(started, entryTokens(entries)...)
		page++
	}
	// Retrieve the data required to build the active
	// votes cache for the records with ongoing votes.
	for _, v := range started {
		// Get the vote details
		token, err := tokenDecode(v)
		if err != nil {
			return err
		}

		reply, err := p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdDetails, "")
		if err != nil {
			return errors.Errorf("PluginRead %x %v %v: %v", token,
				ticketvote.PluginID, ticketvote.CmdDetails, err)
		}
		var dr ticketvote.DetailsReply
		err = json.Unmarshal([]byte(reply), &dr)
		if err != nil {
			return err
		}
		if dr.Vote == nil {
			// Sanity check
			return errors.Errorf("vote details not found "+
				"for record in started inventory %x", token)
		}

		// Add the record to the active votes cache
		p.activeVotesAdd(*dr.Vote)

		// Get the cast votes
		reply, err = p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdResults, "")
		if err != nil {
			return errors.Errorf("PluginRead %x %v %v: %v", token,
				ticketvote.PluginID, ticketvote.CmdResults, err)
		}
		var rr ticketvote.ResultsReply
		err = json.Unmarshal([]byte(reply), &rr)
		if err != nil {
			return err
		}

		// Add the cast votes to the cached active vote entry
		for _, v := range rr.Votes {
			p.activeVotes.AddCastVote(v.Token, v.Ticket, v.VoteBit)
		}
	}

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("ticketvote Cmd: %x %v %v", token, cmd, payload)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(token, payload)
	case ticketvote.CmdStart:
		return p.cmdStart(token, payload)
	case ticketvote.CmdCastBallot:
		return p.cmdCastBallot(token, payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(token)
	case ticketvote.CmdResults:
		return p.cmdResults(token)
	case ticketvote.CmdSummary:
		return p.cmdSummary(token)
	case ticketvote.CmdSubmissions:
		return p.cmdSubmissions(token)
	case ticketvote.CmdInventory:
		return p.cmdInventory(payload)
	case ticketvote.CmdTimestamps:
		return p.cmdTimestamps(token, payload)

		// Internal plugin commands
	case cmdStartRunoffSubmission:
		return p.cmdStartRunoffSubmission(token, payload)
	case cmdRunoffDetails:
		return p.cmdRunoffDetails(token)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeSetRecordStatusPre:
		return p.hookSetRecordStatusPre(payload)
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check. The plugin is provided with the
// tokens for all records in the backend.
//
// This function satisfies the plugins PluginClient interface.
func (p *ticketVotePlugin) Fsck(tokens [][]byte) error {
	log.Tracef("ticketvote Fsck")

	return p.fsck(tokens)
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
		{
			Key:   ticketvote.SettingKeySummariesPageSize,
			Value: strconv.FormatUint(uint64(p.summariesPageSize), 10),
		},
		{
			Key:   ticketvote.SettingKeyInventoryPageSize,
			Value: strconv.FormatUint(uint64(p.inventoryPageSize), 10),
		},
		{
			Key:   ticketvote.SettingKeyTimestampsPageSize,
			Value: strconv.FormatUint(uint64(p.timestampsPageSize), 10),
		},
	}
}

func New(backend backend.Backend, tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*ticketVotePlugin, error) {
	// Plugin settings
	var (
		linkByPeriodMin    int64
		linkByPeriodMax    int64
		voteDurationMin    uint32
		voteDurationMax    uint32
		summariesPageSize  = ticketvote.SettingSummariesPageSize
		inventoryPageSize  = ticketvote.SettingInventoryPageSize
		timestampsPageSize = ticketvote.SettingTimestampsPageSize
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

		case ticketvote.SettingKeySummariesPageSize:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			summariesPageSize = uint32(u)
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeySummariesPageSize, summariesPageSize)

		case ticketvote.SettingKeyInventoryPageSize:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			inventoryPageSize = uint32(u)
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyInventoryPageSize, inventoryPageSize)

		case ticketvote.SettingKeyTimestampsPageSize:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			timestampsPageSize = uint32(u)
			log.Infof("Plugin setting updated: ticketvote %v %v",
				ticketvote.SettingKeyTimestampsPageSize, timestampsPageSize)

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
		activeNetParams:    activeNetParams,
		backend:            backend,
		tstore:             tstore,
		dataDir:            dataDir,
		identity:           id,
		activeVotes:        newActiveVotes(),
		inv:                newInvClient(tstore, backend, inventoryPageSize),
		summaries:          newSummariesClient(tstore),
		subs:               newSubsClient(tstore),
		linkByPeriodMin:    linkByPeriodMin,
		linkByPeriodMax:    linkByPeriodMax,
		voteDurationMin:    voteDurationMin,
		voteDurationMax:    voteDurationMax,
		summariesPageSize:  summariesPageSize,
		inventoryPageSize:  inventoryPageSize,
		timestampsPageSize: timestampsPageSize,
	}, nil
}
