// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlogclient"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

var (
	_ plugins.Client = (*piPlugin)(nil)
)

// piPlugin satisfies the plugins.Client interface.
type piPlugin struct {
	sync.Mutex
	backend         backend.Backend
	tlog            tlogclient.Client
	activeNetParams *chaincfg.Params

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// tokenDecode decodes a token string.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTlog, token)
}

func convertPropStatusFromMDStatus(s backend.MDStatusT) pi.PropStatusT {
	var status pi.PropStatusT
	switch s {
	case backend.MDStatusUnvetted, backend.MDStatusIterationUnvetted:
		status = pi.PropStatusUnvetted
	case backend.MDStatusVetted:
		status = pi.PropStatusPublic
	case backend.MDStatusCensored:
		status = pi.PropStatusCensored
	case backend.MDStatusArchived:
		status = pi.PropStatusAbandoned
	}
	return status
}

func (p *piPlugin) voteSummary(token []byte) (*ticketvote.VoteSummary, error) {
	reply, err := p.backend.VettedPluginCmd(token,
		ticketvote.ID, ticketvote.CmdSummary, "")
	if err != nil {
		return nil, err
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(reply), &sr)
	if err != nil {
		return nil, err
	}
	return &sr.Summary, nil
}

func (p *piPlugin) cmdProposalInv(payload string) (string, error) {
	// Decode payload
	var inv pi.ProposalInv
	err := json.Unmarshal([]byte(payload), &inv)
	if err != nil {
		return "", err
	}

	// Get full record inventory
	ibs, err := p.backend.InventoryByStatus()
	if err != nil {
		return "", err
	}

	// Apply user ID filtering criteria
	if inv.UserID != "" {
		// Lookup the proposal tokens that have been submitted by the
		// specified user.
		ud, err := p.userData(inv.UserID)
		if err != nil {
			return "", fmt.Errorf("userData %v: %v", inv.UserID, err)
		}
		userTokens := make(map[string]struct{}, len(ud.Tokens))
		for _, v := range ud.Tokens {
			userTokens[v] = struct{}{}
		}

		// Compile a list of unvetted tokens categorized by MDStatusT
		// that were submitted by the user.
		filtered := make(map[backend.MDStatusT][]string, len(ibs.Unvetted))
		for status, tokens := range ibs.Unvetted {
			for _, v := range tokens {
				_, ok := userTokens[v]
				if !ok {
					// Proposal was not submitted by the user
					continue
				}

				// Proposal was submitted by the user
				ftokens, ok := filtered[status]
				if !ok {
					ftokens = make([]string, 0, len(tokens))
				}
				filtered[status] = append(ftokens, v)
			}
		}

		// Update unvetted inventory with filtered tokens
		ibs.Unvetted = filtered

		// Compile a list of vetted tokens categorized by MDStatusT that
		// were submitted by the user.
		filtered = make(map[backend.MDStatusT][]string, len(ibs.Vetted))
		for status, tokens := range ibs.Vetted {
			for _, v := range tokens {
				_, ok := userTokens[v]
				if !ok {
					// Proposal was not submitted by the user
					continue
				}

				// Proposal was submitted by the user
				ftokens, ok := filtered[status]
				if !ok {
					ftokens = make([]string, 0, len(tokens))
				}
				filtered[status] = append(ftokens, v)
			}
		}

		// Update vetted inventory with filtered tokens
		ibs.Vetted = filtered
	}

	// Convert MDStatus keys to human readable proposal statuses
	unvetted := make(map[string][]string, len(ibs.Unvetted))
	vetted := make(map[string][]string, len(ibs.Vetted))
	for k, v := range ibs.Unvetted {
		s := pi.PropStatuses[convertPropStatusFromMDStatus(k)]
		unvetted[s] = v
	}
	for k, v := range ibs.Vetted {
		s := pi.PropStatuses[convertPropStatusFromMDStatus(k)]
		vetted[s] = v
	}

	// Prepare reply
	pir := pi.ProposalInvReply{
		Unvetted: unvetted,
		Vetted:   vetted,
	}
	reply, err := json.Marshal(pir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *piPlugin) cmdVoteInventory() (string, error) {
	// Get ticketvote inventory
	r, err := p.backend.VettedPluginCmd([]byte{},
		ticketvote.ID, ticketvote.CmdInventory, "")
	if err != nil {
		return "", fmt.Errorf("VettedPluginCmd %v %v: %v",
			ticketvote.ID, ticketvote.CmdInventory, err)
	}
	var ir ticketvote.InventoryReply
	err = json.Unmarshal([]byte(r), &ir)
	if err != nil {
		return "", err
	}

	// Get vote summaries for all finished proposal votes and
	// categorize by approved/rejected.
	approved := make([]string, 0, len(ir.Finished))
	rejected := make([]string, 0, len(ir.Finished))
	for _, v := range ir.Finished {
		t, err := tokenDecode(v)
		if err != nil {
			return "", err
		}
		vs, err := p.voteSummary(t)
		if err != nil {
			return "", err
		}
		if vs.Approved {
			approved = append(approved, v)
		} else {
			rejected = append(rejected, v)
		}
	}

	// Prepare reply
	vir := pi.VoteInventoryReply{
		Unauthorized: ir.Unauthorized,
		Authorized:   ir.Authorized,
		Started:      ir.Started,
		Approved:     approved,
		Rejected:     rejected,
		BestBlock:    ir.BestBlock,
	}
	reply, err := json.Marshal(vir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Setup() error {
	log.Tracef("Setup")

	// TODO Verify vote and comment plugin dependency

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case pi.CmdProposalInv:
		return p.cmdProposalInv(payload)
	case pi.CmdVoteInventory:
		return p.cmdVoteInventory()
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v %x %v", treeID, plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeNewRecordPost:
		return p.hookNewRecordPost(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	case plugins.HookTypePluginPre:
		return p.hookPluginPre(treeID, token, payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Fsck() error {
	log.Tracef("Fsck")

	return nil
}

func New(backend backend.Backend, tlog tlogclient.Client, settings []backend.PluginSetting, dataDir string, activeNetParams *chaincfg.Params) (*piPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, pi.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &piPlugin{
		dataDir:         dataDir,
		backend:         backend,
		activeNetParams: activeNetParams,
		tlog:            tlog,
	}, nil
}
