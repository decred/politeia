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
	"sort"
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

	// invEntry is a struct used to insert an entry on the ticketvote inventory
	// cache.
	type invEntry struct {
		data entry

		// timestamp holds the last vote status change timestamp, which is used
		// to sort the records from oldest to newest.
		timestamp int64
	}

	// Group inventory entries by their vote statuses and build RFP submissions
	// list for every RFP parent record. While traversing the tokens list, for
	// each record token, verify the coherency of the summaries cache and audit
	// all cast votes against its eligible tickets.
	var (
		unauthorized = make([]*invEntry, 0, len(tokens))
		authorized   = make([]*invEntry, 0, len(tokens))
		started      = make([]*invEntry, 0, len(tokens))
		finished     = make([]*invEntry, 0, len(tokens))
		approved     = make([]*invEntry, 0, len(tokens))
		rejected     = make([]*invEntry, 0, len(tokens))
		ineligible   = make([]*invEntry, 0, len(tokens))

		// rfps holds the submissions of all RFP parents.
		rfps = make(map[string][]string, len(tokens)) // [parentToken][]childTokens
	)

	log.Infof("Starting ticketvote fsck for %v records", len(tokens))

	for _, t := range tokens {
		// Get the partial record for each token.
		r, err := p.tstore.RecordPartial(t, 0, nil, false)
		if err != nil {
			return err
		}

		// Skip ticketvote fsck if record state is unvetted.
		if r.RecordMetadata.State == backend.StateUnvetted {
			continue
		}

		// Decode vote metadata and build submissions map.
		vmd, err := voteMetadataDecode(r.Files)
		if err != nil {
			return err
		}
		if vmd != nil && vmd.LinkTo != "" {
			// Save RFP submissions to further check the coherency of the
			// submissions cache of RFP parents.
			rfps[vmd.LinkTo] = append(rfps[vmd.LinkTo],
				hex.EncodeToString(t))
		}

		// Get best block for summary call.
		bb, err := p.bestBlock()
		if err != nil {
			return err
		}

		// Get the vote summary for each record. The summary call checks if a
		// cache entry exists for that record's vote summary and retrieves it.
		// If it does not exist, it'll build the cache entry from scratch. This
		// verifies the coherency of the summaries cache.
		s, err := p.summary(t, bb)
		if err != nil {
			return err
		}

		// Create inventory entry for each record.
		ie := &invEntry{
			data: entry{
				Token:     hex.EncodeToString(t),
				Status:    s.Status,
				EndHeight: s.EndBlockHeight,
			},
		}

		// Set timestamp field and group tokens according to the record's vote
		// status.
		switch {
		case s.Status == ticketvote.VoteStatusUnauthorized:
			ie.timestamp = r.RecordMetadata.Timestamp
			unauthorized = append(unauthorized, ie)
		case s.Status == ticketvote.VoteStatusAuthorized:
			// Get auth details blobs from tstore.
			auths, err := p.auths(t)
			if err != nil {
				return err
			}
			// Search for latest authorize action timestamp.
			for _, auth := range auths {
				if ticketvote.AuthActionT(auth.Action) ==
					ticketvote.AuthActionAuthorize {
					ie.timestamp = auth.Timestamp
				}
			}
			authorized = append(authorized, ie)
		case s.Status == ticketvote.VoteStatusStarted:
			ie.timestamp = int64(s.StartBlockHeight)
			started = append(started, ie)
		case s.Status == ticketvote.VoteStatusFinished:
			ie.timestamp = int64(s.EndBlockHeight)
			finished = append(finished, ie)
		case s.Status == ticketvote.VoteStatusApproved:
			ie.timestamp = int64(s.EndBlockHeight)
			approved = append(approved, ie)
		case s.Status == ticketvote.VoteStatusRejected:
			ie.timestamp = int64(s.EndBlockHeight)
			rejected = append(rejected, ie)
		case s.Status == ticketvote.VoteStatusIneligible:
			ie.timestamp = r.RecordMetadata.Timestamp
			ineligible = append(ineligible, ie)
		default:
			return fmt.Errorf("invalid vote status for record %v",
				ie.data.Token)
		}

		// Audit finished votes. This verifies that all cast votes use eligible
		// tickets, and that no duplicate votes exist.

		// Skip votes audit if record is unauthorized, authorized or ineligible.
		if s.Status == ticketvote.VoteStatusUnauthorized ||
			s.Status == ticketvote.VoteStatusAuthorized ||
			s.Status == ticketvote.VoteStatusIneligible {
			continue
		}

		// Get vote details for eligible tickets.
		vd, err := p.voteDetails(t)
		if err != nil {
			return err
		}

		// Get vote results for all cast vote details.
		vr, err := p.voteResults(t)
		if err != nil {
			return err
		}

		// Create map access for the eligible tickets.
		eligibles := make(map[string]struct{}, len(vd.EligibleTickets))
		for _, t := range vd.EligibleTickets {
			eligibles[t] = struct{}{}
		}

		// Range through all cast votes and make sure it was cast by a eligible
		// ticket.
		for _, vote := range vr {
			_, ok := eligibles[vote.Ticket]
			if !ok {
				return fmt.Errorf("vote was cast by a not eligible ticket %v"+
					"on record %v", vote.Ticket, vote.Token)
			}
		}
	}

	log.Infof("%v ticketvote summaries verified", len(tokens))
	log.Infof("%v records audited for eligible cast votes", len(tokens))

	// Verify the coherency of the submissions cache.
	for parentToken, submissions := range rfps {
		bToken, err := hex.DecodeString(parentToken)
		if err != nil {
			return err
		}
		cache, err := p.submissionsCache(bToken)
		if err != nil {
			return err
		}
		// Check if every submission is contained in the cache.
		bad := false
		for _, s := range submissions {
			_, ok := cache.Tokens[s]
			if !ok {
				bad = true
				break
			}
		}
		// Check if cache is bad and needs a rebuild.
		if bad {
			err := p.submissionsCacheRemove(bToken)
			if err != nil {
				return err
			}
			for _, s := range submissions {
				err = p.submissionsCacheAdd(parentToken, s)
				if err != nil {
					return err
				}
			}
		}
	}

	log.Infof("%v RFP submission lists verified", len(rfps))

	// Rebuild the ticketvote inventory cache.

	// Sort each vote status group from oldest to newest.
	sort.Slice(unauthorized, func(i, j int) bool {
		return unauthorized[i].timestamp < unauthorized[j].timestamp
	})
	sort.Slice(authorized, func(i, j int) bool {
		return authorized[i].timestamp < authorized[j].timestamp
	})
	sort.Slice(started, func(i, j int) bool {
		return started[i].timestamp < started[j].timestamp
	})
	sort.Slice(finished, func(i, j int) bool {
		return finished[i].timestamp < finished[j].timestamp
	})
	sort.Slice(approved, func(i, j int) bool {
		return approved[i].timestamp < approved[j].timestamp
	})
	sort.Slice(rejected, func(i, j int) bool {
		return rejected[i].timestamp < rejected[j].timestamp
	})
	sort.Slice(ineligible, func(i, j int) bool {
		return ineligible[i].timestamp < ineligible[j].timestamp
	})

	// Delete ticketvote inventory cache before rebuilding.
	err := p.invRemove()
	if err != nil {
		return err
	}

	// Add entries from all status groups to the ticketvote inventory.
	entries := make([]*invEntry, 0, len(tokens))
	entries = append(entries, unauthorized...)
	entries = append(entries, authorized...)
	entries = append(entries, started...)
	entries = append(entries, finished...)
	entries = append(entries, approved...)
	entries = append(entries, rejected...)
	entries = append(entries, ineligible...)
	for _, entry := range entries {
		if entry.data.Status == ticketvote.VoteStatusStarted {
			p.inventoryAdd(entry.data.Token, ticketvote.VoteStatusAuthorized)
			p.inventoryUpdateToStarted(entry.data.Token,
				ticketvote.VoteStatusStarted, entry.data.EndHeight)
			continue
		}
		p.inventoryAdd(entry.data.Token, entry.data.Status)
	}

	log.Infof("%v records added to the ticketvote inventory", len(entries))

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
