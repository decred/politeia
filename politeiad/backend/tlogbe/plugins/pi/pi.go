// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlogclient"
	"github.com/decred/politeia/politeiad/plugins/comments"
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

// isRFP returns whether the provided proposal metadata belongs to an RFP
// proposal.
func isRFP(pm pi.ProposalMetadata) bool {
	return pm.LinkBy != 0
}

// tokenDecode decodes a token string.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTlog, token)
}

// decodeGeneralMetadata decodes and returns the GeneralMetadata from the
// provided backend metadata streams. If a GeneralMetadata is not found, nil is
// returned.
func decodeGeneralMetadata(metadata []backend.MetadataStream) (*pi.GeneralMetadata, error) {
	var generalMD *pi.GeneralMetadata
	for _, v := range metadata {
		if v.ID == pi.MDStreamIDGeneralMetadata {
			var gm pi.GeneralMetadata
			err := json.Unmarshal([]byte(v.Payload), &gm)
			if err != nil {
				return nil, err
			}
			generalMD = &gm
			break
		}
	}
	return generalMD, nil
}

// decodeStatusChanges decodes a JSON byte slice into a []StatusChange slice.
func decodeStatusChanges(payload []byte) ([]pi.StatusChange, error) {
	var statuses []pi.StatusChange
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc pi.StatusChange
		err := d.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		statuses = append(statuses, sc)
	}

	return statuses, nil
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

func (p *piPlugin) cmdProposals(payload string) (string, error) {
	// TODO
	/*
		ps, err := pi.DecodeProposals([]byte(payload))
		if err != nil {
			return "", err
		}

		// Verify state
		var existsFn func([]byte) bool
		switch ps.State {
		case pi.PropStateUnvetted:
			existsFn = p.backend.UnvettedExists
		case pi.PropStateVetted:
			existsFn = p.backend.VettedExists
		default:
			return "", backend.PluginUserError{
				PluginID:  pi.ID,
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
			}
		}

		// Setup the returned map with entries for all tokens that
		// correspond to records.
		// map[token]ProposalPluginData
		proposals := make(map[string]pi.ProposalPluginData, len(ps.Tokens))
		for _, v := range ps.Tokens {
			token, err := tokenDecodeAnyLength(v)
			if err != nil {
				// Not a valid token
				continue
			}
			ok := existsFn(token)
			if !ok {
				// Record doesn't exists
				continue
			}

			// Record exists. Include it in the reply.
			proposals[v] = pi.ProposalPluginData{}
		}

		// Get linked from list for each proposal
		for k, v := range proposals {
			lf, err := p.linkedFrom(k)
			if err != nil {
				return "", fmt.Errorf("linkedFrom %v: %v", k, err)
			}

			// Convert map to a slice
			linkedFrom := make([]string, 0, len(lf.Tokens))
			for token := range lf.Tokens {
				linkedFrom = append(linkedFrom, token)
			}

			v.LinkedFrom = linkedFrom
			proposals[k] = v
		}

		// Get comments count for each proposal
		for k, v := range proposals {
			// Prepare plugin command
			c := comments.Count{
				State: comments.StateT(ps.State),
				Token: k,
			}
			b, err := comments.EncodeCount(c)
			if err != nil {
				return "", err
			}

			// Send plugin command
			reply, err := p.backend.Plugin(comments.ID,
				comments.CmdCount, "", string(b))
			if err != nil {
				return "", fmt.Errorf("backend Plugin %v %v: %v",
					comments.ID, comments.CmdCount, err)
			}

			// Decode reply
			cr, err := comments.DecodeCountReply([]byte(reply))
			if err != nil {
				return "", err
			}

			// Update proposal plugin data
			v.Comments = cr.Count
			proposals[k] = v
		}

		// Prepare reply
		pr := pi.ProposalsReply{
			Proposals: proposals,
		}
		reply, err := pi.EncodeProposalsReply(pr)
		if err != nil {
			return "", err
		}

		return string(reply), nil
	*/
	return "", nil
}

func (p *piPlugin) voteSummary(token []byte) (*ticketvote.Summary, error) {
	t := hex.EncodeToString(token)
	s := ticketvote.Summaries{
		Tokens: []string{t},
	}
	b, err := ticketvote.EncodeSummaries(s)
	if err != nil {
		return nil, err
	}
	r, err := p.backend.Plugin(ticketvote.ID,
		ticketvote.CmdSummaries, "", string(b))
	if err != nil {
		return nil, err
	}
	sr, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	summary, ok := sr.Summaries[t]
	if !ok {
		return nil, fmt.Errorf("proposal not found %v", token)
	}
	return &summary, nil
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

func (p *piPlugin) cmdVoteInventory(payload string) (string, error) {
	// Payload is empty. Nothing to decode.

	// Get ticketvote inventory
	r, err := p.backend.Plugin(ticketvote.ID, ticketvote.CmdInventory, "", "")
	if err != nil {
		return "", fmt.Errorf("ticketvote inventory: %v", err)
	}
	ir, err := ticketvote.DecodeInventoryReply([]byte(r))
	if err != nil {
		return "", err
	}

	// Get vote summaries for all finished proposal votes
	s := ticketvote.Summaries{
		Tokens: ir.Finished,
	}
	b, err := ticketvote.EncodeSummaries(s)
	if err != nil {
		return "", err
	}
	r, err = p.backend.Plugin(ticketvote.ID, ticketvote.CmdSummaries,
		"", string(b))
	if err != nil {
		return "", fmt.Errorf("ticketvote summaries: %v", err)
	}
	sr, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return "", err
	}
	if len(sr.Summaries) != len(ir.Finished) {
		return "", fmt.Errorf("unexpected number of summaries: got %v, want %v",
			len(sr.Summaries), len(ir.Finished))
	}

	// Categorize votes
	approved := make([]string, 0, len(sr.Summaries))
	rejected := make([]string, 0, len(sr.Summaries))
	for token, v := range sr.Summaries {
		if v.Approved {
			approved = append(approved, token)
		} else {
			rejected = append(rejected, token)
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

func (p *piPlugin) hookCommentNew(treeID int64, token []byte, payload string) error {
	var n comments.New
	err := json.Unmarshal([]byte(payload), &n)
	if err != nil {
		return err
	}

	// Verify vote status
	vs, err := p.voteSummary(treeID, token)
	if err != nil {
		return fmt.Errorf("voteSummary: %v", err)
	}
	switch vs.Status {
	case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
		ticketvote.VoteStatusStarted:
		// Comments are allowed on these vote statuses; continue
	default:
		return "", backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
			ErrorContext: "vote has ended; proposal is locked",
		}
	}

	return nil
}

func (p *piPlugin) commentDel(payload string) error {
	// TODO
	/*
		d, err := comments.DecodeDel([]byte(payload))
		if err != nil {
			return "", err
		}

		// Verifying the state, token, and that the record exists is also
		// done in the comments plugin but we duplicate it here so that the
		// vote summary request can complete successfully.

		// Verify state
		switch d.State {
		case comments.StateUnvetted, comments.StateVetted:
			// Allowed; continue
		default:
			return "", backend.PluginUserError{
				PluginID:  pi.ID,
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
			}
		}

		// Verify token
		token, err := tokenDecodeAnyLength(d.Token)
		if err != nil {
			return "", backend.PluginUserError{
				PluginID:  pi.ID,
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
			}
		}

		// Verify record exists
		var exists bool
		switch d.State {
		case comments.StateUnvetted:
			exists = p.backend.UnvettedExists(token)
		case comments.StateVetted:
			exists = p.backend.VettedExists(token)
		default:
			// Should not happen. State has already been validated.
			return "", fmt.Errorf("invalid state %v", d.State)
		}
		if !exists {
			return "", backend.PluginUserError{
				PluginID:  pi.ID,
				ErrorCode: int(pi.ErrorStatusPropNotFound),
			}
		}

		// Verify vote status
		if d.State == comments.StateVetted {
			vs, err := p.voteSummary(d.Token)
			if err != nil {
				return "", fmt.Errorf("voteSummary: %v", err)
			}
			switch vs.Status {
			case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
				ticketvote.VoteStatusStarted:
				// Deleting is allowed on these vote statuses; continue
			default:
				return "", backend.PluginUserError{
					PluginID:     pi.ID,
					ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
					ErrorContext: []string{"vote has ended; proposal is locked"},
				}
			}
		}

		// Send plugin command
		return p.backend.Plugin(comments.ID, comments.CmdDel, "", payload)
	*/
	return nil
}

func (p *piPlugin) commentVote(payload string) error {
	// TODO
	/*
		v, err := comments.DecodeVote([]byte(payload))
		if err != nil {
			return "", err
		}

		// Verifying the state, token, and that the record exists is also
		// done in the comments plugin but we duplicate it here so that the
		// vote summary request can complete successfully.

		// Verify token
		token, err := tokenDecodeAnyLength(v.Token)
		if err != nil {
			return "", backend.PluginUserError{
				PluginID:  pi.ID,
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
			}
		}

		// Verify record exists
		var record *backend.Record
		switch v.State {
		case comments.StateUnvetted:
			record, err = p.backend.GetUnvetted(token, "")
		case comments.StateVetted:
			record, err = p.backend.GetVetted(token, "")
		default:
			// Should not happen. State has already been validated.
			return "", fmt.Errorf("invalid state %v", v.State)
		}
		if err != nil {
			if errors.Is(err, backend.ErrRecordNotFound) {
				return "", backend.PluginUserError{
					PluginID:  pi.ID,
					ErrorCode: int(pi.ErrorStatusPropNotFound),
				}
			}
			return "", fmt.Errorf("get record: %v", err)
		}

		// Verify record status
		status := convertPropStatusFromMDStatus(record.RecordMetadata.Status)
		switch status {
		case pi.PropStatusPublic:
			// Comment votes are only allowed on public proposals; continue
		default:
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropStatusInvalid),
				ErrorContext: []string{"proposal is not public"},
			}
		}

		// Verify vote status
		vs, err := p.voteSummary(v.Token)
		if err != nil {
			return "", fmt.Errorf("voteSummary: %v", err)
		}
		switch vs.Status {
		case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
			ticketvote.VoteStatusStarted:
			// Comment votes are allowed on these vote statuses; continue
		default:
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
				ErrorContext: []string{"vote has ended; proposal is locked"},
			}
		}

		// Send plugin command
		return p.backend.Plugin(comments.ID, comments.CmdVote, "", payload)
	*/
	return nil
}

func (p *piPlugin) ticketVoteStart(payload string) error {
	// TODO If runoff vote, verify that parent record has passed a
	// vote itself. This functionality is specific to pi.

	// Decode payload
	s, err := ticketvote.DecodeStart([]byte(payload))
	if err != nil {
		return "", err
	}
	_ = s

	return nil
}

func (p *piPlugin) hookPluginPre(payload string) error {
	// Decode payload
	var hpp plugins.HookPluginPre
	err := json.Unmarshal([]byte(payload), &hpp)
	if err != nil {
		return err
	}

	// Call plugin hook
	switch hpp.PluginID {
	case comments.ID:
		switch hpp.Cmd {
		case comments.CmdNew:
			return p.hookCommentNew(hpp.Payload)
			// case comments.CmdDel:
			// return p.commentDel(hpp.Payload)
			// case comments.CmdVote:
			// return p.commentVote(hpp.Payload)
		}
	case ticketvote.ID:
		switch hpp.Cmd {
		// case ticketvote.CmdStart:
		// return p.ticketVoteStart(hpp.Payload)
		}
	}

	return nil
}

func (p *piPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Verify a proposal metadata has been included
	pm, err := decodeProposalMetadata(nr.Files)
	if err != nil {
		return err
	}
	if pm == nil {
		return fmt.Errorf("proposal metadata not found")
	}

	// TODO Verify proposal name

	return nil
}

func (p *piPlugin) hookNewRecordPost(payload string) error {
	var nr plugins.HookNewRecord
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Decode GeneralMetadata
	gm, err := decodeGeneralMetadata(nr.Metadata)
	if err != nil {
		return err
	}
	if gm == nil {
		panic("general metadata not found")
	}

	// Add token to the user data cache
	err = p.userDataAddToken(gm.UserID, nr.RecordMetadata.Token)
	if err != nil {
		return err
	}

	return nil
}

func (p *piPlugin) hookEditRecordPre(payload string) error {
	/*
		var er plugins.HookEditRecord
		err := json.Unmarshal([]byte(payload), &er)
		if err != nil {
			return err
		}

		// TODO verify files were changed. Before adding this, verify that
		// politeiad will also error if no files were changed.

		// Verify vote status. This is only required for public proposals.
		if status == pi.PropStatusPublic {
			token := er.RecordMetadata.Token
			s := ticketvote.Summaries{
				Tokens: []string{token},
			}
			b, err := ticketvote.EncodeSummaries(s)
			if err != nil {
				return err
			}
			reply, err := p.backend.Plugin(ticketvote.ID,
				ticketvote.CmdSummaries, "", string(b))
			if err != nil {
				return fmt.Errorf("ticketvote Summaries: %v", err)
			}
			sr, err := ticketvote.DecodeSummariesReply([]byte(reply))
			if err != nil {
				return err
			}
			summary, ok := sr.Summaries[token]
			if !ok {
				return fmt.Errorf("ticketvote summmary not found")
			}
			if summary.Status != ticketvote.VoteStatusUnauthorized {
				e := fmt.Sprintf("vote status got %v, want %v",
					ticketvote.VoteStatuses[summary.Status],
					ticketvote.VoteStatuses[ticketvote.VoteStatusUnauthorized])
				return backend.PluginUserError{
					PluginID:     pi.ID,
					ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
					ErrorContext: e,
				}
			}
		}
	*/

	return nil
}

func (p *piPlugin) hookSetRecordStatusPost(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// Parse the status change metadata
	var sc *pi.StatusChange
	for _, v := range srs.MDAppend {
		if v.ID != pi.MDStreamIDStatusChanges {
			continue
		}

		var sc pi.StatusChange
		err := json.Unmarshal([]byte(v.Payload), &sc)
		if err != nil {
			return err
		}
		break
	}
	if sc == nil {
		return fmt.Errorf("status change append metadata not found")
	}

	// Parse the existing status changes metadata stream
	var statuses []pi.StatusChange
	for _, v := range srs.Current.Metadata {
		if v.ID != pi.MDStreamIDStatusChanges {
			continue
		}

		statuses, err = decodeStatusChanges([]byte(v.Payload))
		if err != nil {
			return err
		}
		break
	}

	// Verify version is the latest version
	if sc.Version != srs.Current.Version {
		e := fmt.Sprintf("version not current: got %v, want %v",
			sc.Version, srs.Current.Version)
		return backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusPropVersionInvalid),
			ErrorContext: e,
		}
	}

	// Verify status change is allowed
	var from pi.PropStatusT
	if len(statuses) == 0 {
		// No previous status changes exist. Proposal is unvetted.
		from = pi.PropStatusUnvetted
	} else {
		from = statuses[len(statuses)-1].Status
	}
	_, isAllowed := pi.StatusChanges[from][sc.Status]
	if !isAllowed {
		e := fmt.Sprintf("from %v to %v status change not allowed",
			from, sc.Status)
		return backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusPropStatusChangeInvalid),
			ErrorContext: e,
		}
	}

	return nil
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
	case pi.CmdProposals:
		return p.cmdProposals(payload)
	case pi.CmdProposalInv:
		return p.cmdProposalInv(payload)
	case pi.CmdVoteInventory:
		return p.cmdVoteInventory(payload)
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
		return p.hookPluginPre(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.Client interface.
func (p *piPlugin) Fsck() error {
	log.Tracef("Fsck")

	// linkedFrom cache

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
