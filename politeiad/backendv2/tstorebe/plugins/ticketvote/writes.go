// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	pluginID = ticketvote.PluginID

	// Blob entry data descriptors
	dataDescriptorAuthDetails     = pluginID + "-auth-v1"
	dataDescriptorVoteDetails     = pluginID + "-vote-v1"
	dataDescriptorCastVoteDetails = pluginID + "-castvote-v1"
	dataDescriptorVoteCollider    = pluginID + "-vcollider-v1"
	dataDescriptorRunoffDetails   = pluginID + "-startrunoff-v1"
)

// cmdAuthorize authorizes a ticket vote or revokes a previous authorization.
func (p *plugin) cmdAuthorize(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var a ticketvote.Authorize
	err := json.Unmarshal([]byte(payload), &a)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, a.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	version := strconv.FormatUint(uint64(a.Version), 10)
	msg := a.Token + version + string(a.Action)
	err = verifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify action
	switch a.Action {
	case ticketvote.AuthActionAuthorize, ticketvote.AuthActionRevoke:
		// These are allowed
	default:
		return "", backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeAuthorizationInvalid),
			ErrorContext: fmt.Sprintf("%v not a valid action", a.Action),
		}
	}

	// Verify record status and version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return "", err
	}
	if r.RecordMetadata.Status != backend.StatusPublic {
		return "", backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeRecordStatusInvalid),
			ErrorContext: "record is not public",
		}
	}
	if a.Version != r.RecordMetadata.Version {
		return "", backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not latest: "+
				"got %v, want %v", a.Version, r.RecordMetadata.Version),
		}
	}

	// Get any previous authorizations to verify that the
	// new action is allowed based on the previous action.
	auths, err := authDetails(tstore, token)
	if err != nil {
		return "", err
	}
	var prevAction ticketvote.AuthActionT
	if len(auths) > 0 {
		prevAction = ticketvote.AuthActionT(auths[len(auths)-1].Action)
	}
	switch {
	case len(auths) == 0:
		// No previous actions. New action must be an authorize.
		if a.Action != ticketvote.AuthActionAuthorize {
			return "", backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeAuthorizationInvalid),
				ErrorContext: "no prev action; action must be authorize",
			}
		}
	case prevAction == ticketvote.AuthActionAuthorize &&
		a.Action != ticketvote.AuthActionRevoke:
		// Previous action was a authorize. This action must be revoke.
		return "", backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeAuthorizationInvalid),
			ErrorContext: "prev action was authorize",
		}
	case prevAction == ticketvote.AuthActionRevoke &&
		a.Action != ticketvote.AuthActionAuthorize:
		// Previous action was a revoke. This action must be authorize.
		return "", backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeAuthorizationInvalid),
			ErrorContext: "prev action was revoke",
		}
	}

	// Save authorization
	receipt := p.identity.SignMessage([]byte(a.Signature))
	auth := ticketvote.AuthDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    string(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}
	err = authDetailsSave(tstore, token, auth)
	if err != nil {
		return "", err
	}

	// Update the inventory
	var status ticketvote.VoteStatusT
	switch a.Action {
	case ticketvote.AuthActionAuthorize:
		status = ticketvote.VoteStatusAuthorized
	case ticketvote.AuthActionRevoke:
		status = ticketvote.VoteStatusUnauthorized
	default:
		// Action has already been validated. This should not happen.
		return "", errors.Errorf("invalid action %v", a.Action)
	}
	err = updateInv(tstore, a.Token, status, auth.Timestamp, nil)
	if err != nil {
		return "", err
	}

	// Prepare reply
	ar := ticketvote.AuthorizeReply{
		Timestamp: auth.Timestamp,
		Receipt:   auth.Receipt,
	}
	reply, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdStart starts a ticket vote.
func (p *plugin) cmdStart(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var s ticketvote.Start
	err := json.Unmarshal([]byte(payload), &s)
	if err != nil {
		return "", err
	}

	// Parse vote type
	if len(s.Starts) == 0 {
		return "", backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeStartDetailsMissing),
			ErrorContext: "no start details found",
		}
	}
	vtype := s.Starts[0].Params.Type

	// Start vote
	var sr *ticketvote.StartReply
	switch vtype {
	case ticketvote.VoteTypeStandard:
		sr, err = p.startStandardVote(tstore, token, s)
		if err != nil {
			return "", err
		}
	case ticketvote.VoteTypeRunoff:
		sr, err = p.startRunoffVote(tstore, token, s)
		if err != nil {
			return "", err
		}
	default:
		return "", backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteTypeInvalid),
		}
	}

	// Prepare reply
	reply, err := json.Marshal(*sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdStartRunoffSub is an internal plugin command that is used to start the
// voting period on a runoff vote submission.
func (p *plugin) cmdStartRunoffSub(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var srs startRunoffSub
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return "", err
	}

	// Sanity check
	sd := srs.StartDetails
	t, err := tokenDecode(sd.Params.Token)
	if err != nil {
		return err
	}
	if !bytes.Equal(token, t) {
		return errors.Errorf("invalid token")
	}

	// Get the runoff details record. This will
	// be saved to the parent record.
	parent, err := tokenDecode(srs.ParentToken)
	if err != nil {
		return err
	}
	rd, err := getRunoffDetails(tstore, token)
	if err != nil {
		return err
	}

	// Sanity check. Verify token is part of
	// the start runoff record submissions.
	var found bool
	for _, v := range srr.Submissions {
		if hex.EncodeToString(token) == v {
			found = true
			break
		}
	}
	if !found {
		// This submission should not be here
		return errors.Errorf("record not in submission list")
	}

	// If the vote has already been started, exit gracefully.
	// This allows us to recover from unexpected errors to
	// the start runoff vote call as it updates the state of
	// multiple records. If the call were to fail before
	// completing, we can simply call the command again with
	// the same arguments and it will pick up where it left
	// off.
	vdp, err := voteDetails(token)
	if err != nil {
		return err
	}
	if vdp != nil {
		// Vote has already been started. Exit gracefully.
		return nil
	}

	// Verify record version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return err
	}
	if r.RecordMetadata.State != backend.StateVetted {
		// This should not be possible
		return errors.Errorf("record is unvetted")
	}
	if sd.Params.Version != r.RecordMetadata.Version {
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not the latest %v: "+
				"got %v, want %v", sd.Params.Token, sd.Params.Version,
				r.RecordMetadata.Version),
		}
	}

	// Save vote details
	receipt := p.identity.SignMessage([]byte(sd.Signature + srr.StartBlockHash))
	vd := ticketvote.VoteDetails{
		Params:           sd.Params,
		PublicKey:        sd.PublicKey,
		Signature:        sd.Signature,
		Receipt:          hex.EncodeToString(receipt[:]),
		StartBlockHeight: srr.StartBlockHeight,
		StartBlockHash:   srr.StartBlockHash,
		EndBlockHeight:   srr.EndBlockHeight,
		EligibleTickets:  srr.EligibleTickets,
	}
	err = voteDetailsSave(tstore, token, vd)
	if err != nil {
		return err
	}

	// Update the inventory
	eed := entryExtraData{
		EndHeight: vd.EndBlockHeight,
	}
	err = updateInv(tstore, vd.Params.Token, ticketvote.VoteStatusStarted,
		time.Now().Unix(), &eed)
	if err != nil {
		return nil, err
	}

	/* TODO active votes
	// Update active votes cache
	p.activeVotesAdd(vd)
	*/

	// Prepare reply
	reply, err = json.Marshal(startRunoffSubmissionReply{})
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// startStandardVote starts a standard vote.
func (p *plugin) startStandardVote(tstore plugins.TstoreClient, token []byte, s ticketvote.Start) (*ticketvote.StartReply, error) {
	// Verify there is only one start details
	if len(s.Starts) != 1 {
		return nil, backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeStartDetailsInvalid),
			ErrorContext: "more than one start details found for " +
				"standard vote",
		}
	}
	sd := s.Starts[0]

	// Verify token
	err := tokenMatches(token, sd.Params.Token)
	if err != nil {
		return nil, err
	}

	// Verify signature
	vb, err := json.Marshal(sd.Params)
	if err != nil {
		return nil, err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	err = verifySignature(sd.Signature, sd.PublicKey, msg)
	if err != nil {
		return nil, err
	}

	// Verify vote options and params
	err = verifyVoteParams(sd.Params, p.settings.voteDurationMin,
		p.settings.voteDurationMax)
	if err != nil {
		return nil, err
	}

	// Verify record status and version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return nil, err
	}
	if r.RecordMetadata.Status != backend.StatusPublic {
		return nil, backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeRecordStatusInvalid),
			ErrorContext: "record is not public",
		}
	}
	if sd.Params.Version != r.RecordMetadata.Version {
		return nil, backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not latest: got %v, "+
				"want %v", sd.Params.Version, r.RecordMetadata.Version),
		}
	}

	// Get dcr blockchain data
	vcp, err := getVoteChainParams(p.backend, sd.Params.Duration,
		uint32(p.net.TicketMaturity))
	if err != nil {
		return nil, err
	}

	// Verify the vote authorization status. Multiple authorization
	// objects may exist. The most recent object is the one that
	// should be checked.
	auths, err := authDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return nil, backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteStatusInvalid),
			ErrorContext: "not authorized",
		}
	}
	action := ticketvote.AuthActionT(auths[len(auths)-1].Action)
	if action != ticketvote.AuthActionAuthorize {
		return nil, backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteStatusInvalid),
			ErrorContext: "not authorized",
		}
	}

	// Verify vote has not already been started
	vdp, err := voteDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if vdp != nil {
		// Vote has already been started
		return nil, backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteStatusInvalid),
			ErrorContext: "vote already started",
		}
	}

	// Save the vote details
	receipt := p.identity.SignMessage([]byte(sd.Signature + vcp.StartBlockHash))
	vd := ticketvote.VoteDetails{
		Params:           sd.Params,
		PublicKey:        sd.PublicKey,
		Signature:        sd.Signature,
		Receipt:          hex.EncodeToString(receipt[:]),
		StartBlockHeight: vcp.StartBlockHeight,
		StartBlockHash:   vcp.StartBlockHash,
		EndBlockHeight:   vcp.EndBlockHeight,
		EligibleTickets:  vcp.EligibleTickets,
	}
	err = voteDetailsSave(tstore, token, vd)
	if err != nil {
		return nil, err
	}

	// Update the inventory
	eed := entryExtraData{
		EndHeight: vd.EndBlockHeight,
	}
	err = updateInv(tstore, vd.Params.Token, ticketvote.VoteStatusStarted,
		time.Now().Unix(), &eed)
	if err != nil {
		return nil, err
	}

	/* TODO active votes
	// Update the active votes cache
	p.activeVotesAdd(vd)
	*/

	return &ticketvote.StartReply{
		Receipt:          vd.Receipt,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}, nil
}

// startRunoff starts the voting period for all submissions in a runoff vote.
// It does this by first saving a startRunoffRecord to the runoff vote parent
// record. Once this has been successfully saved the runoff vote is considered
// to have started. The voting period must now be started on all of the runoff
// vote submissions individually. If any of these calls fail, they can be
// retried.  This function will pick up where it left off.
func (p *plugin) startRunoffVote(tstore plugins.TstoreClient, token []byte, s ticketvote.Start) (*ticketvote.StartReply, error) {
	// Sanity check
	if len(s.Starts) == 0 {
		return nil, errors.Errorf("no start details found")
	}

	// Perform validation that can be done without fetching any records
	// from the backend.
	var (
		mask     = s.Starts[0].Params.Mask
		duration = s.Starts[0].Params.Duration
		quorum   = s.Starts[0].Params.QuorumPercentage
		pass     = s.Starts[0].Params.PassPercentage
		parent   = s.Starts[0].Params.Parent
	)
	for _, v := range s.Starts {
		// Verify vote params are the same for all submissions
		switch {
		case v.Params.Type != ticketvote.VoteTypeRunoff:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteTypeInvalid),
				ErrorContext: fmt.Sprintf("%v got %v, want %v",
					v.Params.Token, v.Params.Type,
					ticketvote.VoteTypeRunoff),
			}
		case v.Params.Mask != mask:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteBitsInvalid),
				ErrorContext: fmt.Sprintf("%v mask invalid: "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.Duration != duration:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteDurationInvalid),
				ErrorContext: fmt.Sprintf("%v duration does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.QuorumPercentage != quorum:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteQuorumInvalid),
				ErrorContext: fmt.Sprintf("%v quorum does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.PassPercentage != pass:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVotePassRateInvalid),
				ErrorContext: fmt.Sprintf("%v pass rate does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.Parent != parent:
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("%v parent does not match; "+
					"all must be the same", v.Params.Token),
			}
		}

		// Verify token
		_, err := tokenDecode(v.Params.Token)
		if err != nil {
			return nil, backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeTokenInvalid),
				ErrorContext: v.Params.Token,
			}
		}

		// Verify parent token
		_, err = tokenDecode(v.Params.Parent)
		if err != nil {
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeTokenInvalid),
				ErrorContext: fmt.Sprintf("parent token %v invalid",
					v.Params.Parent),
			}
		}

		// Verify signature
		vb, err := json.Marshal(v.Params)
		if err != nil {
			return nil, err
		}
		msg := hex.EncodeToString(util.Digest(vb))
		err = verifySignature(v.Signature, v.PublicKey, msg)
		if err != nil {
			return nil, err
		}

		// Verify vote options and params. Vote optoins are
		// required to be approve and reject.
		err = verifyVoteParams(v.Params, p.settings.voteDurationMin,
			p.settings.voteDurationMax)
		if err != nil {
			return nil, err
		}
	}

	// Verify that this plugin command is being executed on the
	// parent record.
	if hex.EncodeToString(token) != parent {
		return nil, backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteParentInvalid),
			ErrorContext: fmt.Sprintf("runoff vote must be started "+
				"on the parent record %v", parent),
		}
	}

	// Save a start runoff record to the parent record.
	srr, err := p.startRunoffForParent(token, s)
	if err != nil {
		return nil, err
	}

	// Start the voting period on each runoff vote submissions.
	// This is done using the startRunoffSubmission internal
	// plugin command.
	for _, v := range s.Starts {
		token, err = tokenDecode(v.Params.Token)
		if err != nil {
			return nil, err
		}
		srs := startRunoffSubmission{
			ParentToken:  v.Params.Parent,
			StartDetails: v,
		}
		b, err := json.Marshal(srs)
		if err != nil {
			return nil, err
		}
		_, err = p.backend.PluginWrite(token, ticketvote.PluginID,
			cmdStartRunoffSubmission, string(b))
		if err != nil {
			var ue backend.PluginError
			if errors.As(err, &ue) {
				return nil, err
			}
			return nil, errors.Errorf("PluginWrite %x %v %v: %v",
				token, ticketvote.PluginID,
				cmdStartRunoffSubmission, err)
		}
	}

	return &ticketvote.StartReply{
		StartBlockHeight: srr.StartBlockHeight,
		StartBlockHash:   srr.StartBlockHash,
		EndBlockHeight:   srr.EndBlockHeight,
		EligibleTickets:  srr.EligibleTickets,
	}, nil
}

// startRunoffForParent saves a startRunoffRecord to the parent record. Once
// this has been saved the runoff vote is considered to be started and the
// voting period on individual runoff vote submissions can be started.
func (p *plugin) startRunoffForParent(token []byte, s ticketvote.Start) (*startRunoffRecord, error) {
	// Check if the runoff vote data already exists on the parent tree.
	srr, err := p.startRunoffRecord(token)
	if err != nil {
		return nil, err
	}
	if srr != nil {
		// We already have a start runoff record for this runoff vote.
		// This can happen if the previous call failed due to an
		// unexpected error such as a network error. Return the start
		// runoff record so we can pick up where we left off.
		return srr, nil
	}

	// Get blockchain data
	var (
		mask     = s.Starts[0].Params.Mask
		duration = s.Starts[0].Params.Duration
		quorum   = s.Starts[0].Params.QuorumPercentage
		pass     = s.Starts[0].Params.PassPercentage
	)
	vcp, err := p.voteChainParams(duration)
	if err != nil {
		return nil, err
	}

	// Verify parent has a LinkBy and the LinkBy deadline is expired.
	files := []string{
		ticketvote.FileNameVoteMetadata,
	}
	r, err := tstore.RecordPartial(token, 0, files, false)
	if err != nil {
		if errors.Is(err, backend.ErrRecordNotFound) {
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("parent record not "+
					"found %x", token),
			}
		}
		return nil, errors.Errorf("RecordPartial: %v", err)
	}
	if r.RecordMetadata.State != backend.StateVetted {
		// This should not be possible
		return nil, errors.Errorf("record is unvetted")
	}
	vm, err := voteMetadataDecode(r.Files)
	if err != nil {
		return nil, err
	}
	if vm == nil || vm.LinkBy == 0 {
		return nil, backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteParentInvalid),
			ErrorContext: fmt.Sprintf("%x is not a runoff vote "+
				"parent", token),
		}
	}
	if vm.LinkBy > time.Now().Unix() {
		return nil, backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeLinkByNotExpired),
			ErrorContext: fmt.Sprintf("parent record %x linkby "+
				"deadline (%v) has not expired yet", token, vm.LinkBy),
		}
	}

	// Compile a list of the expected submissions that should be in the
	// runoff vote. This will be all of the public records that have
	// linked to the parent record. The parent record's submissions
	// list will include abandoned proposals that need to be filtered
	// out.
	lf, err := p.submissionsCache(token)
	if err != nil {
		return nil, err
	}
	expected := make(map[string]struct{}, len(lf.Tokens)) // [token]struct{}
	for k := range lf.Tokens {
		token, err := tokenDecode(k)
		if err != nil {
			return nil, err
		}
		r, err := p.recordAbridged(token)
		if err != nil {
			return nil, err
		}
		if r.RecordMetadata.Status != backend.StatusPublic {
			// This record is not public and should not be included
			// in the runoff vote.
			continue
		}

		// This is a public record that is part of the parent record's
		// submissions list. It is required to be in the runoff vote.
		expected[k] = struct{}{}
	}

	// Verify that there are no extra submissions in the runoff vote
	for _, v := range s.Starts {
		_, ok := expected[v.Params.Token]
		if !ok {
			// This submission should not be here
			return nil, backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeStartDetailsInvalid),
				ErrorContext: fmt.Sprintf("record %v should "+
					"not be included", v.Params.Token),
			}
		}
	}

	// Verify that the runoff vote is not missing any submissions
	subs := make(map[string]struct{}, len(s.Starts))
	for _, v := range s.Starts {
		subs[v.Params.Token] = struct{}{}
	}
	for k := range expected {
		_, ok := subs[k]
		if !ok {
			// This records is missing from the runoff vote
			return nil, backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeStartDetailsMissing),
				ErrorContext: k,
			}
		}
	}

	// Prepare start runoff record
	submissions := make([]string, 0, len(subs))
	for k := range subs {
		submissions = append(submissions, k)
	}
	srr = &startRunoffRecord{
		Submissions:      submissions,
		Mask:             mask,
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
		StartBlockHeight: vcp.StartBlockHeight,
		StartBlockHash:   vcp.StartBlockHash,
		EndBlockHeight:   vcp.EndBlockHeight,
		EligibleTickets:  vcp.EligibleTickets,
	}

	// Save start runoff record
	err = p.startRunoffRecordSave(token, *srr)
	if err != nil {
		return nil, err
	}

	return srr, nil
}

// verifyVoteParams verifies that the params of a ticket vote are within
// acceptable values.
func verifyVoteParams(vote ticketvote.VoteParams, voteDurationMin, voteDurationMax uint32) error {
	// Verify vote type
	switch vote.Type {
	case ticketvote.VoteTypeStandard:
		// This is allowed
	case ticketvote.VoteTypeRunoff:
		// This is allowed
	default:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteTypeInvalid),
		}
	}

	// Verify vote params
	switch {
	case vote.Duration > voteDurationMax:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteDurationInvalid),
			ErrorContext: fmt.Sprintf("duration %v exceeds max "+
				"duration %v", vote.Duration, voteDurationMax),
		}
	case vote.Duration < voteDurationMin:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteDurationInvalid),
			ErrorContext: fmt.Sprintf("duration %v under min "+
				"duration %v", vote.Duration, voteDurationMin),
		}
	case vote.QuorumPercentage > 100:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteQuorumInvalid),
			ErrorContext: fmt.Sprintf("quorum percent %v exceeds "+
				"100 percent", vote.QuorumPercentage),
		}
	case vote.PassPercentage > 100:
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVotePassRateInvalid),
			ErrorContext: fmt.Sprintf("pass percent %v exceeds "+
				"100 percent", vote.PassPercentage),
		}
	}

	// Verify the vote options. Different vote types have
	// different requirements.
	if len(vote.Options) == 0 {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeVoteOptionsInvalid),
			ErrorContext: "no vote options found",
		}
	}
	switch vote.Type {
	case ticketvote.VoteTypeStandard, ticketvote.VoteTypeRunoff:
		// These vote types only allow for approve/reject votes.
		// Verify that the only options present are approve/reject
		// and that they use the vote option IDs specified by the
		// ticketvote API.
		if len(vote.Options) != 2 {
			return backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteOptionsInvalid),
				ErrorContext: fmt.Sprintf("got %v options, want 2",
					len(vote.Options)),
			}
		}
		// map[optionID]found
		options := map[string]bool{
			ticketvote.VoteOptionIDApprove: false,
			ticketvote.VoteOptionIDReject:  false,
		}
		for _, v := range vote.Options {
			switch v.ID {
			case ticketvote.VoteOptionIDApprove:
				options[v.ID] = true
			case ticketvote.VoteOptionIDReject:
				options[v.ID] = true
			}
		}
		missing := make([]string, 0, 2)
		for k, v := range options {
			if !v {
				// Option ID was not found
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			return backend.PluginError{
				PluginID:  ticketvote.PluginID,
				ErrorCode: uint32(ticketvote.ErrorCodeVoteOptionsInvalid),
				ErrorContext: fmt.Sprintf("vote option IDs not found: %v",
					strings.Join(missing, ",")),
			}
		}
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Options {
		err := verifyVoteBit(vote.Options, vote.Mask, v.Bit)
		if err != nil {
			return backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeVoteBitsInvalid),
				ErrorContext: err.Error(),
			}
		}
	}

	// Verify parent token
	switch {
	case vote.Type == ticketvote.VoteTypeStandard && vote.Parent != "":
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeVoteParentInvalid),
			ErrorContext: "parent token should not be provided " +
				"for a standard vote",
		}
	case vote.Type == ticketvote.VoteTypeRunoff:
		_, err := tokenDecode(vote.Parent)
		if err != nil {
			return backend.PluginError{
				PluginID:     ticketvote.PluginID,
				ErrorCode:    uint32(ticketvote.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("invalid parent %v", vote.Parent),
			}
		}
	}

	return nil
}

// verifyVoteBit verifies that the vote bit corresponds to a valid vote option.
func verifyVoteBit(options []ticketvote.VoteOption, mask, bit uint64) error {
	if len(options) == 0 {
		return errors.Errorf("no vote options found")
	}
	if bit == 0 {
		return errors.Errorf("invalid bit 0x%x", bit)
	}

	// Verify bit is included in mask
	if mask&bit != bit {
		return errors.Errorf("invalid mask 0x%x bit 0x%x", mask, bit)
	}

	// Verify bit is included in vote options
	for _, v := range options {
		if v.Bit == bit {
			// Bit matches one of the options. We're done.
			return nil
		}
	}

	return errors.Errorf("bit 0x%x not found in vote options", bit)
}

// voteChainParams represent the dcr blockchain parameters for a ticket vote.
type voteChainParams struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
}

// getVoteChainParams fetches and returns the voteChainParams for a ticket
// vote.
func getVoteChainParams(backend backend.Backend, duration, ticketMaturity uint32) (*voteChainParams, error) {
	// Get the best block height
	bb, err := bestBlock(backend)
	if err != nil {
		return nil, err
	}

	// Find the snapshot height. Subtract the ticket maturity from the
	// block height to get into unforkable territory.
	snapshotHeight := bb - ticketMaturity

	// Fetch the block details for the snapshot height. We need the
	// block hash in order to fetch the ticket pool snapshot.
	bd := dcrdata.BlockDetails{
		Height: snapshotHeight,
	}
	payload, err := json.Marshal(bd)
	if err != nil {
		return nil, err
	}
	reply, err := backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdBlockDetails, string(payload))
	if err != nil {
		return nil, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdBlockDetails, err)
	}
	var bdr dcrdata.BlockDetailsReply
	err = json.Unmarshal([]byte(reply), &bdr)
	if err != nil {
		return nil, err
	}
	if bdr.Block.Hash == "" {
		return nil, errors.Errorf("invalid block hash for height %v",
			snapshotHeight)
	}
	snapshotHash := bdr.Block.Hash

	// Fetch the ticket pool snapshot
	tp := dcrdata.TicketPool{
		BlockHash: snapshotHash,
	}
	payload, err = json.Marshal(tp)
	if err != nil {
		return nil, err
	}
	reply, err = backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdTicketPool, string(payload))
	if err != nil {
		return nil, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdTicketPool, err)
	}
	var tpr dcrdata.TicketPoolReply
	err = json.Unmarshal([]byte(reply), &tpr)
	if err != nil {
		return nil, err
	}
	if len(tpr.Tickets) == 0 {
		return nil, errors.Errorf("no tickets found for block %v %v",
			snapshotHeight, snapshotHash)
	}

	// The start block height has the ticket maturity subtracted from
	// it to prevent forking issues. This means we the vote starts in
	// the past. The ticket maturity needs to be added to the end block
	// height to correct for this.
	endBlockHeight := snapshotHeight + duration + ticketMaturity

	return &voteChainParams{
		StartBlockHeight: snapshotHeight,
		StartBlockHash:   snapshotHash,
		EndBlockHeight:   endBlockHeight,
		EligibleTickets:  tpr.Tickets,
	}, nil
}
