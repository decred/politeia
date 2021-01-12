// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

const (
	// Filenames of cached data saved to the pi plugin data dir.
	fnLinkedFrom = "{token}-linkedfrom.json"
	fnUserData   = "{userid}.json"
)

var (
	_ pluginClient = (*piPlugin)(nil)
)

// piPlugin satisfies the pluginClient interface.
type piPlugin struct {
	sync.Mutex
	backend         backend.Backend
	tlog            tlogClient
	activeNetParams *chaincfg.Params

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// linkedFrom is the the structure that is updated and cached for proposal A
// when proposal B links to proposal A. Proposals can link to one another using
// the ProposalMetadata LinkTo field. The linkedFrom list contains all
// proposals that have linked to proposal A. The list will only contain public
// proposals. The linkedFrom list is saved to disk in the pi plugin data dir,
// specifying the parent proposal token in the filename.
//
// Example: the linked from list for an RFP proposal will contain all public
// RFP submissions. The cached list can be found in the pi plugin data dir
// at the path specified by linkedFromPath().
type linkedFrom struct {
	Tokens map[string]struct{} `json:"tokens"`
}

// linkedFromPath returns the path to the linkedFrom list for the provided
// proposal token.
func (p *piPlugin) linkedFromPath(token string) string {
	fn := strings.Replace(fnLinkedFrom, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn)
}

// linkedFromWithLock return the linkedFrom list for the provided proposal
// token.
//
// This function must be called WITH the lock held.
func (p *piPlugin) linkedFromWithLock(token string) (*linkedFrom, error) {
	fp := p.linkedFromPath(token)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty linked from list.
			return &linkedFrom{
				Tokens: make(map[string]struct{}),
			}, nil
		}
	}

	var lf linkedFrom
	err = json.Unmarshal(b, &lf)
	if err != nil {
		return nil, err
	}

	return &lf, nil
}

// linkedFrom return the linkedFrom list for the provided proposal token.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFrom(token string) (*linkedFrom, error) {
	p.Lock()
	defer p.Unlock()

	return p.linkedFromWithLock(token)
}

// linkedFromSaveWithLock saves the provided linkedFrom list to the pi plugin
// data dir.
//
// This function must be called WITH the lock held.
func (p *piPlugin) linkedFromSaveWithLock(token string, lf linkedFrom) error {
	b, err := json.Marshal(lf)
	if err != nil {
		return err
	}
	fp := p.linkedFromPath(token)
	return ioutil.WriteFile(fp, b, 0664)
}

// linkedFromAdd updates the cached linkedFrom list for the parentToken, adding
// the childToken to the list.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFromAdd(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parentToken)
	if errors.Is(err, errRecordNotFound) {
		return fmt.Errorf("linkedFromWithLock %v: %v", parentToken, err)
	}

	// Update list
	lf.Tokens[childToken] = struct{}{}

	// Save list
	return p.linkedFromSaveWithLock(parentToken, *lf)
}

// linkedFromDel updates the cached linkedFrom list for the parentToken,
// deleting the childToken from the list.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFromDel(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parentToken)
	if err != nil {
		return fmt.Errorf("linkedFromWithLock %v: %v", parentToken, err)
	}

	// Update list
	delete(lf.Tokens, childToken)

	// Save list
	return p.linkedFromSaveWithLock(parentToken, *lf)
}

// userData contains cached pi plugin data for a specific user. The userData
// JSON is saved to disk in the pi plugin data dir. The user ID is included in
// the filename.
type userData struct {
	// Tokens contains a list of all the proposals that have been
	// submitted by this user. This data is cached so that the
	// ProposalInv command can filter proposals by user ID.
	Tokens []string `json:"tokens"`
}

// userDataPath returns the filepath to the cached userData struct for the
// specified user.
func (p *piPlugin) userDataPath(userID string) string {
	fn := strings.Replace(fnUserData, "{userid}", userID, 1)
	return filepath.Join(p.dataDir, fn)
}

// userDataWithLock returns the cached userData struct for the specified user.
//
// This function must be called WITH the lock held.
func (p *piPlugin) userDataWithLock(userID string) (*userData, error) {
	fp := p.userDataPath(userID)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty userData.
			return &userData{
				Tokens: []string{},
			}, nil
		}
	}

	var ud userData
	err = json.Unmarshal(b, &ud)
	if err != nil {
		return nil, err
	}

	return &ud, nil
}

// userData returns the cached userData struct for the specified user.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) userData(userID string) (*userData, error) {
	p.Lock()
	defer p.Unlock()

	return p.userDataWithLock(userID)
}

// userDataSaveWithLock saves the provided userData to the pi plugin data dir.
//
// This function must be called WITH the lock held.
func (p *piPlugin) userDataSaveWithLock(userID string, ud userData) error {
	b, err := json.Marshal(ud)
	if err != nil {
		return err
	}

	fp := p.userDataPath(userID)
	return ioutil.WriteFile(fp, b, 0664)
}

// userDataAddToken adds the provided token to the cached userData for the
// provided user.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) userDataAddToken(userID string, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	ud, err := p.userDataWithLock(userID)
	if err != nil {
		return err
	}

	// Add token
	ud.Tokens = append(ud.Tokens, token)

	// Save changes
	return p.userDataSaveWithLock(userID, *ud)
}

// isRFP returns whether the provided proposal metadata belongs to an RFP
// proposal.
func isRFP(pm pi.ProposalMetadata) bool {
	return pm.LinkBy != 0
}

// decodeProposalMetadata decodes and returns the ProposalMetadata from the
// provided backend files. If a ProposalMetadata is not found, nil is returned.
func decodeProposalMetadata(files []backend.File) (*pi.ProposalMetadata, error) {
	var pm *pi.ProposalMetadata
	for _, v := range files {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			pm, err = pi.DecodeProposalMetadata(b)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	return pm, nil
}

// decodeGeneralMetadata decodes and returns the GeneralMetadata from the
// provided backend metadata streams. If a GeneralMetadata is not found, nil is
// returned.
func decodeGeneralMetadata(metadata []backend.MetadataStream) (*pi.GeneralMetadata, error) {
	var gm *pi.GeneralMetadata
	var err error
	for _, v := range metadata {
		if v.ID == pi.MDStreamIDGeneralMetadata {
			gm, err = pi.DecodeGeneralMetadata([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
			break
		}
	}
	return gm, nil
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
		token, err := util.ConvertStringToken(v)
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
}

func (p *piPlugin) voteSummary(token string) (*ticketvote.Summary, error) {
	s := ticketvote.Summaries{
		Tokens: []string{token},
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
	summary, ok := sr.Summaries[token]
	if !ok {
		return nil, fmt.Errorf("proposal not found %v", token)
	}
	return &summary, nil
}

func (p *piPlugin) cmdProposalInv(payload string) (string, error) {
	// Decode payload
	inv, err := pi.DecodeProposalInv([]byte(payload))
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
	reply, err := pi.EncodeProposalInvReply(pir)
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
	reply, err := pi.EncodeVoteInventoryReply(vir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *piPlugin) commentNew(payload string) (string, error) {
	n, err := comments.DecodeNew([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verifying the state, token, and that the record exists is also
	// done in the comments plugin but we duplicate it here so that the
	// vote summary request can complete successfully.

	// Verify state
	switch n.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  pi.ID,
			ErrorCode: int(pi.ErrorStatusPropStateInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(n.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  pi.ID,
			ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
		}
	}

	// Verify record exists
	var exists bool
	switch n.State {
	case comments.StateUnvetted:
		exists = p.backend.UnvettedExists(token)
	case comments.StateVetted:
		exists = p.backend.VettedExists(token)
	default:
		// Should not happen. State has already been validated.
		return "", fmt.Errorf("invalid state %v", n.State)
	}
	if !exists {
		return "", backend.PluginUserError{
			PluginID:  pi.ID,
			ErrorCode: int(pi.ErrorStatusPropNotFound),
		}
	}

	// Verify vote status
	if n.State == comments.StateVetted {
		vs, err := p.voteSummary(n.Token)
		if err != nil {
			return "", fmt.Errorf("voteSummary: %v", err)
		}
		switch vs.Status {
		case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
			ticketvote.VoteStatusStarted:
			// Comments are allowed on these vote statuses; continue
		default:
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
				ErrorContext: []string{"vote has ended; proposal is locked"},
			}
		}
	}

	// Send plugin command
	return p.backend.Plugin(comments.ID, comments.CmdNew, "", payload)
}

func (p *piPlugin) commentDel(payload string) (string, error) {
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
	token, err := util.ConvertStringToken(d.Token)
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
}

func (p *piPlugin) commentVote(payload string) (string, error) {
	v, err := comments.DecodeVote([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verifying the state, token, and that the record exists is also
	// done in the comments plugin but we duplicate it here so that the
	// vote summary request can complete successfully.

	// Verify state
	switch v.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  pi.ID,
			ErrorCode: int(pi.ErrorStatusPropStateInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(v.Token)
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
}

func (p *piPlugin) ticketVoteStart(payload string) (string, error) {
	// Decode payload
	s, err := ticketvote.DecodeStart([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify work needs to be done
	if len(s.Starts) == 0 {
		return "", backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusStartDetailsInvalid),
			ErrorContext: []string{"no start details found"},
		}
	}

	// Sanity check. This pass through command should only be used for
	// RFP runoff votes.
	if s.Starts[0].Params.Type != ticketvote.VoteTypeRunoff {
		return "", fmt.Errorf("not a runoff vote")
	}

	// Get RFP token. Just use the parent token from the first vote
	// params. If the different vote params use different parent
	// tokens, the ticketvote plugin will catch it.
	rfpToken := s.Starts[0].Params.Parent
	rfpTokenb, err := tokenDecode(rfpToken)
	if err != nil {
		e := fmt.Sprintf("invalid rfp token '%v'", rfpToken)
		return "", backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusVoteParentInvalid),
			ErrorContext: []string{e},
		}
	}

	// Get RFP record
	rfp, err := p.backend.GetVetted(rfpTokenb, "")
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			e := fmt.Sprintf("rfp not found %x", rfpToken)
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusVoteParentInvalid),
				ErrorContext: []string{e},
			}
		}
		return "", fmt.Errorf("GetVetted %x: %v", rfpToken, err)
	}

	// Verify RFP linkby has expired. The runoff vote is not allowed to
	// start until after the linkby deadline has passed.
	rfpPM, err := decodeProposalMetadata(rfp.Files)
	if err != nil {
		return "", err
	}
	if rfpPM == nil {
		e := fmt.Sprintf("rfp is not a proposal %v", rfpToken)
		return "", backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusVoteParentInvalid),
			ErrorContext: []string{e},
		}
	}
	isExpired := rfpPM.LinkBy < time.Now().Unix()
	isMainNet := p.activeNetParams.Name == chaincfg.MainNetParams().Name
	switch {
	case !isExpired && isMainNet:
		e := fmt.Sprintf("rfp %v linkby deadline not met %v",
			rfpToken, rfpPM.LinkBy)
		return "", backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorStatusLinkByNotExpired),
			ErrorContext: []string{e},
		}
	case !isExpired:
		// Allow the vote to be started before the link by deadline
		// expires on testnet and simnet only. This makes testing the
		// RFP process easier.
		log.Warnf("RFP linkby deadline has not been met; disregarding " +
			"since this is not mainnet")
	}

	// Compile a list of the expected RFP submissions that should be in
	// the runoff vote. This will be all of the public proposals that
	// have linked to the RFP. The RFP's linked from list will include
	// abandoned proposals that need to be filtered out.
	linkedFrom, err := p.linkedFrom(rfpToken)
	if err != nil {
		return "", err
	}
	// map[token]struct{}
	expected := make(map[string]struct{}, len(linkedFrom.Tokens))
	for k := range linkedFrom.Tokens {
		token, err := tokenDecode(k)
		if err != nil {
			return "", err
		}
		r, err := p.backend.GetVetted(token, "")
		if err != nil {
			return "", err
		}
		if r.RecordMetadata.Status != backend.MDStatusVetted {
			// This proposal is not public and should not be included in
			// the runoff vote.
			continue
		}

		// This is a public proposal that is part of the RFP linked from
		// list. It is required to be in the runoff vote.
		expected[k] = struct{}{}
	}

	// Verify that there are no extra submissions in the runoff vote
	for _, v := range s.Starts {
		_, ok := expected[v.Params.Token]
		if !ok {
			// This submission should not be here.
			e := fmt.Sprintf("found token that should not be included: %v",
				v.Params.Token)
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusStartDetailsInvalid),
				ErrorContext: []string{e},
			}
		}
	}

	// Verify that the runoff vote is not missing any submissions
	subs := make(map[string]struct{}, len(s.Starts))
	for _, v := range s.Starts {
		subs[v.Params.Token] = struct{}{}
	}
	for token := range expected {
		_, ok := subs[token]
		if !ok {
			// This proposal is missing from the runoff vote
			return "", backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusStartDetailsMissing),
				ErrorContext: []string{token},
			}
		}
	}

	// Pi plugin validation complete! Pass the plugin command to the
	// ticketvote plugin.
	return p.backend.Plugin(ticketvote.ID, ticketvote.CmdStart, "", payload)
}

func (p *piPlugin) passThrough(pt pi.PassThrough) (string, error) {
	switch pt.PluginID {
	case comments.ID:
		switch pt.PluginCmd {
		case comments.CmdNew:
			return p.commentNew(pt.Payload)
		case comments.CmdDel:
			return p.commentDel(pt.Payload)
		case comments.CmdVote:
			return p.commentVote(pt.Payload)
		default:
			return "", fmt.Errorf("invalid %v plugin cmd '%v'",
				pt.PluginID, pt.PluginCmd)
		}
	case ticketvote.ID:
		switch pt.PluginCmd {
		case ticketvote.CmdStart:
			return p.ticketVoteStart(pt.Payload)
		default:
			return "", fmt.Errorf("invalid %v plugin cmd '%v'",
				pt.PluginID, pt.PluginCmd)
		}
	default:
		return "", fmt.Errorf("invalid plugin id '%v'", pt.PluginID)
	}
}

func (p *piPlugin) cmdPassThrough(payload string) (string, error) {
	// Decode payload
	pt, err := pi.DecodePassThrough([]byte(payload))
	if err != nil {
		return "", err
	}

	// Execute command
	r, err := p.passThrough(*pt)
	if err != nil {
		return "", err
	}

	// Prepare reply
	ptr := pi.PassThroughReply{
		Payload: r,
	}
	reply, err := pi.EncodePassThroughReply(ptr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *piPlugin) hookNewRecordPre(payload string) error {
	nr, err := decodeHookNewRecord([]byte(payload))
	if err != nil {
		return err
	}

	// Decode ProposalMetadata
	pm, err := decodeProposalMetadata(nr.Files)
	if err != nil {
		return err
	}
	if pm == nil {
		return fmt.Errorf("proposal metadata not found")
	}

	// TODO is linkby validated anywhere? It should be validated here
	// and in the edit proposal.

	// Verify the linkto is an RFP and that the RFP is eligible to be
	// linked to. We currently only allow linking to RFP proposals that
	// have been approved by a ticket vote.
	if pm.LinkTo != "" {
		if isRFP(*pm) {
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"an rfp cannot have linkto set"},
			}
		}
		tokenb, err := hex.DecodeString(pm.LinkTo)
		if err != nil {
			return backend.PluginUserError{

				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"invalid hex"},
			}
		}
		r, err := p.backend.GetVetted(tokenb, "")
		if err != nil {
			if errors.Is(err, backend.ErrRecordNotFound) {
				return backend.PluginUserError{
					PluginID:     pi.ID,
					ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
					ErrorContext: []string{"proposal not found"},
				}
			}
			return err
		}
		linkToPM, err := decodeProposalMetadata(r.Files)
		if err != nil {
			return err
		}
		if linkToPM == nil {
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if !isRFP(*linkToPM) {
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"proposal not an rfp"},
			}
		}
		if time.Now().Unix() > linkToPM.LinkBy {
			// Link by deadline has expired. New links are not allowed.
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"rfp link by deadline expired"},
			}
		}
		s := ticketvote.Summaries{
			Tokens: []string{pm.LinkTo},
		}
		b, err := ticketvote.EncodeSummaries(s)
		if err != nil {
			return err
		}
		reply, err := p.backend.Plugin(ticketvote.ID,
			ticketvote.CmdSummaries, "", string(b))
		if err != nil {
			return fmt.Errorf("Plugin %v %v: %v",
				ticketvote.ID, ticketvote.CmdSummaries, err)
		}
		sr, err := ticketvote.DecodeSummariesReply([]byte(reply))
		if err != nil {
			return err
		}
		summary, ok := sr.Summaries[pm.LinkTo]
		if !ok {
			return fmt.Errorf("summary not found %v", pm.LinkTo)
		}
		if !summary.Approved {
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"rfp vote not approved"},
			}
		}
	}

	return nil
}

func (p *piPlugin) hookNewRecordPost(payload string) error {
	nr, err := decodeHookNewRecord([]byte(payload))
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
	er, err := decodeHookEditRecord([]byte(payload))
	if err != nil {
		return err
	}

	// TODO verify files were changed. Before adding this, verify that
	// politeiad will also error if no files were changed.

	// Verify that the linkto has not changed. This only applies to
	// public proposal. Unvetted proposals are allowed to change their
	// linkto.
	status := convertPropStatusFromMDStatus(er.Current.RecordMetadata.Status)
	if status == pi.PropStatusPublic {
		pmCurr, err := decodeProposalMetadata(er.Current.Files)
		if err != nil {
			return err
		}
		pmNew, err := decodeProposalMetadata(er.FilesAdd)
		if err != nil {
			return err
		}
		if pmCurr.LinkTo != pmNew.LinkTo {
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusPropLinkToInvalid),
				ErrorContext: []string{"linkto cannot change on public proposal"},
			}
		}
	}

	// TODO verify linkto is allowed

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
				ticketvote.VoteStatus[summary.Status],
				ticketvote.VoteStatus[ticketvote.VoteStatusUnauthorized])
			return backend.PluginUserError{
				PluginID:     pi.ID,
				ErrorCode:    int(pi.ErrorStatusVoteStatusInvalid),
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

func (p *piPlugin) hookSetRecordStatusPost(payload string) error {
	srs, err := decodeHookSetRecordStatus([]byte(payload))
	if err != nil {
		return err
	}

	// Parse the status change metadata
	var sc *pi.StatusChange
	for _, v := range srs.MDAppend {
		if v.ID != pi.MDStreamIDStatusChanges {
			continue
		}

		sc, err = pi.DecodeStatusChange([]byte(v.Payload))
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

		statuses, err = pi.DecodeStatusChanges([]byte(v.Payload))
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
			ErrorContext: []string{e},
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
			ErrorContext: []string{e},
		}
	}

	// If the LinkTo field has been set then the linkedFrom
	// list might need to be updated for the proposal that is being
	// linked to, depending on the status change that is being made.
	pm, err := decodeProposalMetadata(srs.Current.Files)
	if err != nil {
		return err
	}
	if pm != nil && pm.LinkTo != "" {
		// Link from has been set. Check if the status change requires
		// the parent proposal's linked from list to be updated.
		var (
			parentToken = pm.LinkTo
			childToken  = srs.RecordMetadata.Token
		)
		switch srs.RecordMetadata.Status {
		case backend.MDStatusVetted:
			// Proposal has been made public. Add child token to parent
			// token's linked from list.
			err := p.linkedFromAdd(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("linkedFromAdd: %v", err)
			}
		case backend.MDStatusCensored:
			// Proposal has been censored. Delete child token from parent
			// token's linked from list.
			err := p.linkedFromDel(parentToken, childToken)
			if err != nil {
				return fmt.Errorf("linkedFromDel: %v", err)
			}
		}
	}

	return nil
}

// setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *piPlugin) setup() error {
	log.Tracef("pi setup")

	// TODO Verify vote and comment plugin dependency

	return nil
}

// cmd executes a plugin command.
//
// This function satisfies the pluginClient interface.
func (p *piPlugin) cmd(cmd, payload string) (string, error) {
	log.Tracef("pi cmd: %v %v", cmd, payload)

	switch cmd {
	case pi.CmdProposals:
		return p.cmdProposals(payload)
	case pi.CmdProposalInv:
		return p.cmdProposalInv(payload)
	case pi.CmdVoteInventory:
		return p.cmdVoteInventory(payload)
	case pi.CmdPassThrough:
		return p.cmdPassThrough(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// hook executes a plugin hook.
//
// This function satisfies the pluginClient interface.
func (p *piPlugin) hook(h hookT, payload string) error {
	log.Tracef("pi hook: %v", hooks[h])

	switch h {
	case hookNewRecordPre:
		return p.hookNewRecordPre(payload)
	case hookNewRecordPost:
		return p.hookNewRecordPost(payload)
	case hookEditRecordPre:
		return p.hookEditRecordPre(payload)
	case hookSetRecordStatusPost:
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

// fsck performs a plugin filesystem check.
//
// This function satisfies the pluginClient interface.
func (p *piPlugin) fsck() error {
	log.Tracef("pi fsck")

	// linkedFrom cache

	return nil
}

func newPiPlugin(backend backend.Backend, tlog tlogClient, settings []backend.PluginSetting, activeNetParams *chaincfg.Params) (*piPlugin, error) {
	// Unpack plugin settings
	var dataDir string
	for _, v := range settings {
		switch v.Key {
		case pluginSettingDataDir:
			dataDir = v.Value
		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Verify plugin settings
	switch {
	case dataDir == "":
		return nil, fmt.Errorf("plugin setting not found: %v",
			pluginSettingDataDir)
	}

	// Create the plugin data directory
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
