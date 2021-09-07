// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"strconv"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
)

var (
	_ plugins.PluginClient = (*plugin)(nil)
)

// plugin implements the the ticketvote plugin API. The ticketvote plugin
// extends a record with dcr ticket voting functionality.
//
// This struct satisfies the PluginClient interface.
type plugin struct {
	backend  backend.Backend
	net      chaincfg.Params // Decred network
	settings settings        // Plugin settings

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity identity.FullIdentity
}

// New returns a new ticketvote plugin.
func New(backend backend.Backend, bs backend.BackendSettings, ps []backend.PluginSetting) (*plugin, error) {
	settings, err := parseSettings(ps, bs.Net)
	if err != nil {
		return nil, err
	}
	return &plugin{
		backend:  backend,
		net:      bs.Net,
		identity: bs.Identity,
		settings: *settings,
	}, nil
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Setup() error {
	log.Tracef("ticketvote Setup")

	/* TODO add setup back in
	// Verify plugin dependencies
	var dcrdataFound bool
	for _, v := range p.backend.PluginInventory() {
		if v.ID == dcrdata.PluginID {
			dcrdataFound = true
		}
	}
	if !dcrdataFound {
		return errors.Errorf("plugin dependency not registered: %v",
			dcrdata.PluginID)
	}

	// Update the inventory with the current best block. Retrieving
	// the inventory will cause it to update.
	log.Infof("Updating vote inventory")

	bestBlock, err := p.bestBlock()
	if err != nil {
		return errors.Errorf("bestBlock: %v", err)
	}
	inv, err := p.Inventory(bestBlock)
	if err != nil {
		return errors.Errorf("Inventory: %v", err)
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
			return errors.Errorf("PluginRead %x %v %v: %v",
				token, ticketvote.PluginID, ticketvote.CmdDetails, err)
		}
		var dr ticketvote.DetailsReply
		err = json.Unmarshal([]byte(reply), &dr)
		if err != nil {
			return err
		}
		if dr.Vote == nil {
			// Something is wrong. This should not happen.
			return errors.Errorf("vote details not found for record in "+
				"started inventory %x", token)
		}

		// Add active votes entry
		p.activeVotesAdd(*dr.Vote)

		// Get cast votes
		reply, err = p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdResults, "")
		if err != nil {
			return errors.Errorf("PluginRead %x %v %v: %v",
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
	*/

	return nil
}

// Write executes a read/write plugin command. All operations are executed
// atomically by tstore when using this method. The plugin does not need to
// worry about concurrency issues.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Write(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("ticketvote Write: %x %v %v", token, cmd, payload)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(tstore, token, payload)
	case ticketvote.CmdStart:
		return p.cmdStart(tstore, token, payload)

	// case ticketvote.CmdCastBallot:
	// return p.cmdCastBallot(tstore, token, payload)

	// Internal plugin commands
	case cmdStartRunoffSub:
		return p.cmdStartRunoffSub(tstore, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Read executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Read(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("ticketvote Read: %x %v %v", token, cmd, payload)

	/*
		switch cmd {
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
		case cmdRunoffDetails:
			return p.cmdRunoffDetails(token)
		}
	*/

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Hook(tstore plugins.TstoreClient, h plugins.HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v", plugins.Hooks[h])

	/* TODO Add hooks back in
	switch h {
	case plugins.HookRecordNewPre:
		return p.hookRecordNewPre(payload)
	case plugins.HookRecordEditPre:
		return p.hookRecordEditPre(payload)
	case plugins.HookRecordSetStatusPre:
		return p.hookRecordSetStatusPre(payload)
	case plugins.HookRecordSetStatusPost:
		return p.hookRecordSetStatusPost(payload)
	}
	*/

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Fsck() error {
	log.Tracef("ticketvote Fsck")

	// Verify all caches

	// Audit all finished votes
	//  - All votes that were cast were eligible
	//  - No duplicate votes

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *plugin) Settings() []backend.PluginSetting {
	log.Tracef("ticketvote Settings")

	return []backend.PluginSetting{
		{
			Key:   ticketvote.SettingKeyLinkByPeriodMin,
			Value: strconv.FormatInt(p.settings.linkByPeriodMin, 10),
		},
		{
			Key:   ticketvote.SettingKeyLinkByPeriodMax,
			Value: strconv.FormatInt(p.settings.linkByPeriodMax, 10),
		},
		{
			Key:   ticketvote.SettingKeyVoteDurationMin,
			Value: strconv.FormatUint(uint64(p.settings.voteDurationMin), 10),
		},
		{
			Key:   ticketvote.SettingKeyVoteDurationMax,
			Value: strconv.FormatUint(uint64(p.settings.voteDurationMax), 10),
		},
	}
}

// settings contains all of the ticketvote plugin settings.
type settings struct {
	linkByPeriodMin int64  // In seconds
	linkByPeriodMax int64  // In seconds
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks
}

// parseSettings parses the ticketvote settings from a list of generic backend
// plugin settings.
func parseSettings(ps []backend.PluginSetting, net chaincfg.Params) (*settings, error) {
	// Set plugin settings to defaults. These will be overwritten
	// with provided settings.
	var (
		linkByPeriodMin int64
		linkByPeriodMax int64
		voteDurationMin uint32
		voteDurationMax uint32
	)
	switch net.Name {
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
		return nil, errors.Errorf("invalid network %v", net.Name)
	}

	// Override defaults with any passed in settings
	for _, v := range ps {
		switch v.Key {
		case ticketvote.SettingKeyLinkByPeriodMin:
			i, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("parse %v: ParseInt(%v): %v",
					v.Key, v.Value, err)
			}
			linkByPeriodMin = i

		case ticketvote.SettingKeyLinkByPeriodMax:
			i, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("parse %v: ParseInt(%v): %v",
					v.Key, v.Value, err)
			}
			linkByPeriodMax = i

		case ticketvote.SettingKeyVoteDurationMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("parse %v: ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMin = uint32(u)

		case ticketvote.SettingKeyVoteDurationMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("parse %v: ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMax = uint32(u)

		default:
			return nil, errors.Errorf("invalid plugin setting '%v'", v.Key)
		}

		log.Infof("Plugin setting updated: ticketvote %v %v", v.Key, v.Value)
	}

	return &settings{
		linkByPeriodMin: linkByPeriodMin,
		linkByPeriodMax: linkByPeriodMax,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
	}, nil
}
