// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"time"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// TODO www package references should be completely gone from this file
// TODO use pi policies. Should the policies be defined in the pi plugin
// or the pi api spec?
// TODO ensure plugins can't write data using short proposal token.
// TODO politeiad needs batched calls for retrieving unvetted and vetted
// records.

const (
	// MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
)

var (
	// validProposalName contains the regex that matches a valid
	// proposal name.
	validProposalName = regexp.MustCompile(proposalNameRegex())

	// statusReasonRequired contains the list of proposal statuses that
	// require an accompanying reason to be given for the status change.
	statusReasonRequired = map[piv1.PropStatusT]struct{}{
		piv1.PropStatusCensored:  {},
		piv1.PropStatusAbandoned: {},
	}

	// errProposalNotFound is emitted when a proposal is not found in
	// politeiad for a specified token and version.
	errProposalNotFound = errors.New("proposal not found")
)

// tokenIsValid returns whether the provided string is a valid politeiad
// censorship record token. This CAN BE EITHER the full length token or the
// token prefix.
//
// Short tokens should only be used when retrieving data. Data that is written
// to disk should always reference the full length token.
func tokenIsValid(token string) bool {
	// Verify token size
	switch {
	case len(token) == pdv1.TokenPrefixLength:
		// Token is a short proposal token
	case len(token) == pdv1.TokenSizeTlog*2:
		// Token is a full length token
	default:
		// Unknown token size
		return false
	}

	// Verify token is valid hex
	_, err := hex.DecodeString(token)
	return err == nil
}

// tokenIsFullLength returns whether the provided string a is valid, full
// length politeiad censorship record token. Short tokens are considered
// invalid by this function.
func tokenIsFullLength(token string) bool {
	b, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	if len(b) != pdv1.TokenSizeTlog {
		return false
	}
	return true
}

// proposalNameIsValid returns whether the provided proposal name is a valid.
func proposalNameIsValid(name string) bool {
	return validProposalName.MatchString(name)
}

// proposalNameRegex returns a regex string for validating the proposal name.
func proposalNameRegex() string {
	var validProposalNameBuffer bytes.Buffer
	validProposalNameBuffer.WriteString("^[")

	for _, supportedChar := range www.PolicyProposalNameSupportedChars {
		if len(supportedChar) > 1 {
			validProposalNameBuffer.WriteString(supportedChar)
		} else {
			validProposalNameBuffer.WriteString(`\` + supportedChar)
		}
	}
	minNameLength := strconv.Itoa(www.PolicyMinProposalNameLength)
	maxNameLength := strconv.Itoa(www.PolicyMaxProposalNameLength)
	validProposalNameBuffer.WriteString("]{")
	validProposalNameBuffer.WriteString(minNameLength + ",")
	validProposalNameBuffer.WriteString(maxNameLength + "}$")

	return validProposalNameBuffer.String()
}

// proposalName parses the proposal name from the ProposalMetadata and returns
// it. An empty string will be returned if any errors occur or if a name is not
// found.
func proposalName(pr piv1.ProposalRecord) string {
	var name string
	for _, v := range pr.Metadata {
		if v.Hint == piv1.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			pm, err := pi.DecodeProposalMetadata(b)
			if err != nil {
				return ""
			}
			name = pm.Name
		}
	}
	return name
}

// proposalRecordFillInUser fills in all user fields that are store in the
// user database and not in politeiad.
func proposalRecordFillInUser(pr piv1.ProposalRecord, u user.User) piv1.ProposalRecord {
	pr.UserID = u.ID.String()
	pr.Username = u.Username
	return pr
}

// commentFillInUser populates the provided comment with user data that is not
// store in politeiad and must be populated separately after pulling the
// comment from politeiad.
func commentFillInUser(c piv1.Comment, u user.User) piv1.Comment {
	c.Username = u.Username
	return c
}

func convertUserErrorFromSignatureError(err error) piv1.UserErrorReply {
	var e util.SignatureError
	var s piv1.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = piv1.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = piv1.ErrorStatusSignatureInvalid
		}
	}
	return piv1.UserErrorReply{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func convertPropStateFromPi(s piv1.PropStateT) pi.PropStateT {
	switch s {
	case piv1.PropStateUnvetted:
		return pi.PropStateUnvetted
	case piv1.PropStateVetted:
		return pi.PropStateVetted
	}
	return pi.PropStateInvalid
}

func convertRecordStatusFromPropStatus(s piv1.PropStatusT) pdv1.RecordStatusT {
	switch s {
	case piv1.PropStatusUnreviewed:
		return pdv1.RecordStatusNotReviewed
	case piv1.PropStatusPublic:
		return pdv1.RecordStatusPublic
	case piv1.PropStatusCensored:
		return pdv1.RecordStatusCensored
	case piv1.PropStatusAbandoned:
		return pdv1.RecordStatusArchived
	}
	return pdv1.RecordStatusInvalid
}

func convertFileFromMetadata(m piv1.Metadata) pdv1.File {
	var name string
	switch m.Hint {
	case piv1.HintProposalMetadata:
		name = pi.FileNameProposalMetadata
	}
	return pdv1.File{
		Name:    name,
		MIME:    mimeTypeTextUTF8,
		Digest:  m.Digest,
		Payload: m.Payload,
	}
}

func convertFileFromPi(f piv1.File) pdv1.File {
	return pdv1.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertFilesFromPi(files []piv1.File) []pdv1.File {
	f := make([]pdv1.File, 0, len(files))
	for _, v := range files {
		f = append(f, convertFileFromPi(v))
	}
	return f
}

func convertPropStatusFromPD(s pdv1.RecordStatusT) piv1.PropStatusT {
	switch s {
	case pdv1.RecordStatusNotFound:
		// Intentionally omitted. No corresponding PropStatusT.
	case pdv1.RecordStatusNotReviewed:
		return piv1.PropStatusUnreviewed
	case pdv1.RecordStatusCensored:
		return piv1.PropStatusCensored
	case pdv1.RecordStatusPublic:
		return piv1.PropStatusPublic
	case pdv1.RecordStatusUnreviewedChanges:
		return piv1.PropStatusUnreviewed
	case pdv1.RecordStatusArchived:
		return piv1.PropStatusAbandoned
	}
	return piv1.PropStatusInvalid
}

func convertCensorshipRecordFromPD(cr pdv1.CensorshipRecord) piv1.CensorshipRecord {
	return piv1.CensorshipRecord{
		Token:     cr.Token,
		Merkle:    cr.Merkle,
		Signature: cr.Signature,
	}
}

func convertFilesFromPD(f []pdv1.File) ([]piv1.File, []piv1.Metadata) {
	files := make([]piv1.File, 0, len(f))
	metadata := make([]piv1.Metadata, 0, len(f))
	for _, v := range f {
		switch v.Name {
		case pi.FileNameProposalMetadata:
			metadata = append(metadata, piv1.Metadata{
				Hint:    piv1.HintProposalMetadata,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		default:
			files = append(files, piv1.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		}
	}
	return files, metadata
}

func convertProposalRecordFromPD(r pdv1.Record, state piv1.PropStateT) (*piv1.ProposalRecord, error) {
	// Decode metadata streams
	var (
		gm  *pi.GeneralMetadata
		sc  = make([]pi.StatusChange, 0, 16)
		err error
	)
	for _, v := range r.Metadata {
		switch v.ID {
		case pi.MDStreamIDGeneralMetadata:
			gm, err = pi.DecodeGeneralMetadata([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		case pi.MDStreamIDStatusChanges:
			sc, err = pi.DecodeStatusChanges([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert to pi types
	files, metadata := convertFilesFromPD(r.Files)
	status := convertPropStatusFromPD(r.Status)

	statuses := make([]piv1.StatusChange, 0, len(sc))
	for _, v := range sc {
		statuses = append(statuses, piv1.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    piv1.PropStatusT(v.Status),
			Reason:    v.Reason,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
		})
	}

	// Some fields are intentionally omitted because they are either
	// user data that needs to be pulled from the user database or they
	// are politeiad plugin data that needs to be retrieved using a
	// plugin command.
	return &piv1.ProposalRecord{
		Version:          r.Version,
		Timestamp:        gm.Timestamp,
		State:            state,
		Status:           status,
		UserID:           "", // Intentionally omitted
		Username:         "", // Intentionally omitted
		PublicKey:        gm.PublicKey,
		Signature:        gm.Signature,
		Comments:         0, // Intentionally omitted
		Statuses:         statuses,
		Files:            files,
		Metadata:         metadata,
		LinkedFrom:       []string{}, // Intentionally omitted
		CensorshipRecord: convertCensorshipRecordFromPD(r.CensorshipRecord),
	}, nil
}

func convertCommentsStateFromPi(s piv1.PropStateT) comments.StateT {
	switch s {
	case piv1.PropStateUnvetted:
		return comments.StateUnvetted
	case piv1.PropStateVetted:
		return comments.StateVetted
	}
	return comments.StateInvalid
}

func convertPropStateFromComments(s comments.StateT) piv1.PropStateT {
	switch s {
	case comments.StateUnvetted:
		return piv1.PropStateUnvetted
	case comments.StateVetted:
		return piv1.PropStateVetted
	}
	return piv1.PropStateInvalid
}

func convertCommentStateFromPi(s piv1.PropStateT) comments.StateT {
	switch s {
	case piv1.PropStateUnvetted:
		return comments.StateUnvetted
	case piv1.PropStateVetted:
		return comments.StateVetted
	}
	return comments.StateInvalid
}

func convertCommentVoteFromPi(cv piv1.CommentVoteT) comments.VoteT {
	switch cv {
	case piv1.CommentVoteDownvote:
		return comments.VoteUpvote
	case piv1.CommentVoteUpvote:
		return comments.VoteDownvote
	}
	return comments.VoteInvalid
}

func convertCommentFromPlugin(c comments.Comment) piv1.Comment {
	return piv1.Comment{
		UserID:    c.UserID,
		Username:  "", // Intentionally omitted, needs to be pulled from userdb
		State:     convertPropStateFromComments(c.State),
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		PublicKey: c.PublicKey,
		Signature: c.Signature,
		CommentID: c.CommentID,
		Timestamp: c.Timestamp,
		Receipt:   c.Receipt,
		Downvotes: c.Downvotes,
		Upvotes:   c.Upvotes,
		Censored:  c.Deleted,
		Reason:    c.Reason,
	}
}

func convertCommentVoteFromPlugin(v comments.VoteT) piv1.CommentVoteT {
	switch v {
	case comments.VoteDownvote:
		return piv1.CommentVoteDownvote
	case comments.VoteUpvote:
		return piv1.CommentVoteUpvote
	}
	return piv1.CommentVoteInvalid
}

func convertCommentVoteDetailsFromPlugin(cv []comments.CommentVote) []piv1.CommentVoteDetails {
	c := make([]piv1.CommentVoteDetails, 0, len(cv))
	for _, v := range cv {
		c = append(c, piv1.CommentVoteDetails{
			UserID:    v.UserID,
			State:     convertPropStateFromComments(v.State),
			Token:     v.Token,
			CommentID: v.CommentID,
			Vote:      convertCommentVoteFromPlugin(v.Vote),
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return c
}

func convertVoteAuthActionFromPi(a piv1.VoteAuthActionT) ticketvote.AuthActionT {
	switch a {
	case piv1.VoteAuthActionAuthorize:
		return ticketvote.AuthActionAuthorize
	case piv1.VoteAuthActionRevoke:
		return ticketvote.AuthActionRevoke
	default:
		return ticketvote.AuthActionAuthorize
	}
}

func convertVoteAuthorizeFromPi(va piv1.VoteAuthorize) ticketvote.Authorize {
	return ticketvote.Authorize{
		Token:     va.Token,
		Version:   va.Version,
		Action:    convertVoteAuthActionFromPi(va.Action),
		PublicKey: va.PublicKey,
		Signature: va.Signature,
	}
}

func convertVoteAuthsFromPi(auths []piv1.VoteAuthorize) []ticketvote.Authorize {
	a := make([]ticketvote.Authorize, 0, len(auths))
	for _, v := range auths {
		a = append(a, convertVoteAuthorizeFromPi(v))
	}
	return a
}

func convertVoteTypeFromPi(t piv1.VoteT) ticketvote.VoteT {
	switch t {
	case piv1.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case piv1.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	return ticketvote.VoteTypeInvalid
}

func convertVoteParamsFromPi(v piv1.VoteParams) ticketvote.VoteParams {
	tv := ticketvote.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeFromPi(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Parent:           v.Parent,
	}
	// Convert vote options
	vo := make([]ticketvote.VoteOption, 0, len(v.Options))
	for _, vi := range v.Options {
		vo = append(vo, ticketvote.VoteOption{
			ID:          vi.ID,
			Description: vi.Description,
			Bit:         vi.Bit,
		})
	}
	tv.Options = vo

	return tv
}

func convertStartDetailsFromPi(sd piv1.StartDetails) ticketvote.StartDetails {
	return ticketvote.StartDetails{
		Params:    convertVoteParamsFromPi(sd.Params),
		PublicKey: sd.PublicKey,
		Signature: sd.Signature,
	}
}

func convertVoteStartFromPi(vs piv1.VoteStart) ticketvote.Start {
	starts := make([]ticketvote.StartDetails, 0, len(vs.Starts))
	for _, v := range vs.Starts {
		starts = append(starts, convertStartDetailsFromPi(v))
	}
	return ticketvote.Start{
		Starts: starts,
	}
}

func convertVoteStartsFromPi(starts []piv1.VoteStart) []ticketvote.Start {
	s := make([]ticketvote.Start, 0, len(starts))
	for _, v := range starts {
		s = append(s, convertVoteStartFromPi(v))
	}
	return s
}

func convertCastVotesFromPi(votes []piv1.CastVote) []ticketvote.CastVote {
	cv := make([]ticketvote.CastVote, 0, len(votes))
	for _, v := range votes {
		cv = append(cv, ticketvote.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
		})
	}
	return cv
}

func convertVoteErrorFromPlugin(e ticketvote.VoteErrorT) piv1.VoteErrorT {
	switch e {
	case ticketvote.VoteErrorInvalid:
		return piv1.VoteErrorInvalid
	case ticketvote.VoteErrorInternalError:
		return piv1.VoteErrorInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return piv1.VoteErrorRecordNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return piv1.VoteErrorVoteBitInvalid
	case ticketvote.VoteErrorVoteStatusInvalid:
		return piv1.VoteErrorVoteStatusInvalid
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return piv1.VoteErrorTicketAlreadyVoted
	case ticketvote.VoteErrorTicketNotEligible:
		return piv1.VoteErrorTicketNotEligible
	default:
		return piv1.VoteErrorInternalError
	}
}

func convertVoteTypeFromPlugin(t ticketvote.VoteT) piv1.VoteT {
	switch t {
	case ticketvote.VoteTypeStandard:
		return piv1.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return piv1.VoteTypeRunoff
	}
	return piv1.VoteTypeInvalid

}

func convertVoteParamsFromPlugin(v ticketvote.VoteParams) piv1.VoteParams {
	vp := piv1.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeFromPlugin(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
	}
	vo := make([]piv1.VoteOption, 0, len(v.Options))
	for _, o := range v.Options {
		vo = append(vo, piv1.VoteOption{
			ID:          o.ID,
			Description: o.Description,
			Bit:         o.Bit,
		})
	}
	vp.Options = vo

	return vp
}

func convertCastVoteRepliesFromPlugin(replies []ticketvote.CastVoteReply) []piv1.CastVoteReply {
	r := make([]piv1.CastVoteReply, 0, len(replies))
	for _, v := range replies {
		r = append(r, piv1.CastVoteReply{
			Ticket:       v.Ticket,
			Receipt:      v.Receipt,
			ErrorCode:    convertVoteErrorFromPlugin(v.ErrorCode),
			ErrorContext: v.ErrorContext,
		})
	}
	return r
}

func convertVoteDetailsFromPlugin(vd ticketvote.VoteDetails) piv1.VoteDetails {
	return piv1.VoteDetails{
		Params:           convertVoteParamsFromPlugin(vd.Params),
		PublicKey:        vd.PublicKey,
		Signature:        vd.Signature,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}
}

func convertAuthDetailsFromPlugin(auths []ticketvote.AuthDetails) []piv1.AuthDetails {
	a := make([]piv1.AuthDetails, 0, len(auths))
	for _, v := range auths {
		a = append(a, piv1.AuthDetails{
			Token:     v.Token,
			Version:   v.Version,
			Action:    v.Action,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return a
}

func convertCastVoteDetailsFromPlugin(votes []ticketvote.CastVoteDetails) []piv1.CastVoteDetails {
	vs := make([]piv1.CastVoteDetails, 0, len(votes))
	for _, v := range votes {
		vs = append(vs, piv1.CastVoteDetails{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   v.Receipt,
		})
	}
	return vs
}

func convertProposalVotesFromPlugin(votes map[string]ticketvote.RecordVote) map[string]piv1.ProposalVote {
	pv := make(map[string]piv1.ProposalVote, len(votes))
	for k, v := range votes {
		var vdp *piv1.VoteDetails
		if v.Vote != nil {
			vd := convertVoteDetailsFromPlugin(*v.Vote)
			vdp = &vd
		}
		pv[k] = piv1.ProposalVote{
			Auths: convertAuthDetailsFromPlugin(v.Auths),
			Vote:  vdp,
		}
	}
	return pv
}

func convertVoteStatusFromPlugin(s ticketvote.VoteStatusT) piv1.VoteStatusT {
	switch s {
	case ticketvote.VoteStatusInvalid:
		return piv1.VoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return piv1.VoteStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		return piv1.VoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return piv1.VoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return piv1.VoteStatusFinished
	default:
		return piv1.VoteStatusInvalid
	}
}

func convertVoteSummaryFromPlugin(s ticketvote.Summary) piv1.VoteSummary {
	results := make([]piv1.VoteResult, 0, len(s.Results))
	for _, v := range s.Results {
		results = append(results, piv1.VoteResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.VoteBit,
			Votes:       v.Votes,
		})
	}
	return piv1.VoteSummary{
		Type:             convertVoteTypeFromPlugin(s.Type),
		Status:           convertVoteStatusFromPlugin(s.Status),
		Duration:         s.Duration,
		StartBlockHeight: s.StartBlockHeight,
		StartBlockHash:   s.StartBlockHash,
		EndBlockHeight:   s.EndBlockHeight,
		EligibleTickets:  s.EligibleTickets,
		QuorumPercentage: s.QuorumPercentage,
		PassPercentage:   s.PassPercentage,
		Results:          results,
		Approved:         s.Approved,
	}
}

func convertVoteSummariesFromPlugin(ts map[string]ticketvote.Summary) map[string]piv1.VoteSummary {
	s := make(map[string]piv1.VoteSummary, len(ts))
	for k, v := range ts {
		s[k] = convertVoteSummaryFromPlugin(v)
	}
	return s
}

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

// proposalRecords returns the ProposalRecord for each of the provided proposal
// requests. If a token does not correspond to an actual proposal then it will
// not be included in the returned map.
func (p *politeiawww) proposalRecords(ctx context.Context, state piv1.PropStateT, reqs []piv1.ProposalRequest, includeFiles bool) (map[string]piv1.ProposalRecord, error) {
	// Get politeiad records
	props := make([]piv1.ProposalRecord, 0, len(reqs))
	for _, v := range reqs {
		var r *pdv1.Record
		var err error
		switch state {
		case piv1.PropStateUnvetted:
			// Unvetted politeiad record
			r, err = p.getUnvetted(ctx, v.Token, v.Version)
			if err != nil {
				return nil, err
			}
		case piv1.PropStateVetted:
			// Vetted politeiad record
			r, err = p.getVetted(ctx, v.Token, v.Version)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown state %v", state)
		}

		if r.Status == pdv1.RecordStatusNotFound {
			// Record wasn't found. Don't include token in the results.
			continue
		}

		pr, err := convertProposalRecordFromPD(*r, state)
		if err != nil {
			return nil, err
		}

		// Remove files if specified. The Metadata objects will still be
		// returned.
		if !includeFiles {
			pr.Files = []piv1.File{}
		}

		props = append(props, *pr)
	}

	// Verify we've got some results
	if len(props) == 0 {
		return map[string]piv1.ProposalRecord{}, nil
	}

	// Get proposal plugin data
	tokens := make([]string, 0, len(props))
	for _, v := range props {
		tokens = append(tokens, v.CensorshipRecord.Token)
	}
	ps := pi.Proposals{
		State:  convertPropStateFromPi(state),
		Tokens: tokens,
	}
	psr, err := p.piProposals(ctx, ps)
	if err != nil {
		return nil, fmt.Errorf("proposalPluginData: %v", err)
	}
	for k, v := range props {
		token := v.CensorshipRecord.Token
		d, ok := psr.Proposals[token]
		if !ok {
			return nil, fmt.Errorf("proposal plugin data not found %v", token)
		}
		props[k].Comments = d.Comments
		props[k].LinkedFrom = d.LinkedFrom
	}

	// Get user data
	pubkeys := make([]string, 0, len(props))
	for _, v := range props {
		pubkeys = append(pubkeys, v.PublicKey)
	}
	ur, err := p.db.UsersGetByPubKey(pubkeys)
	if err != nil {
		return nil, err
	}
	for k, v := range props {
		token := v.CensorshipRecord.Token
		u, ok := ur[v.PublicKey]
		if !ok {
			return nil, fmt.Errorf("user not found for pubkey %v from proposal %v",
				v.PublicKey, token)
		}
		props[k] = proposalRecordFillInUser(v, u)
	}

	// Convert proposals to a map
	proposals := make(map[string]piv1.ProposalRecord, len(props))
	for _, v := range props {
		proposals[v.CensorshipRecord.Token] = v
	}

	return proposals, nil
}

// proposalRecord returns the proposal record for the provided token and
// version. A blank version will return the most recent version. A
// errProposalNotFound error will be returned if a proposal is not found for
// the provided token/version combination.
func (p *politeiawww) proposalRecord(ctx context.Context, state piv1.PropStateT, token, version string) (*piv1.ProposalRecord, error) {
	prs, err := p.proposalRecords(ctx, state, []piv1.ProposalRequest{
		{
			Token:   token,
			Version: version,
		},
	}, true)
	if err != nil {
		return nil, err
	}
	pr, ok := prs[token]
	if !ok {
		return nil, errProposalNotFound
	}
	return &pr, nil
}

// proposalRecordLatest returns the latest version of the proposal record for
// the provided token. A errProposalNotFound error will be returned if a
// proposal is not found for the provided token.
func (p *politeiawww) proposalRecordLatest(ctx context.Context, state piv1.PropStateT, token string) (*piv1.ProposalRecord, error) {
	return p.proposalRecord(ctx, state, token, "")
}

func (p *politeiawww) verifyProposalMetadata(pm piv1.ProposalMetadata) error {
	// Verify name
	if !proposalNameIsValid(pm.Name) {
		return piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPropNameInvalid,
			ErrorContext: []string{proposalNameRegex()},
		}
	}

	// Verify linkto
	if pm.LinkTo != "" {
		if !tokenIsFullLength(pm.LinkTo) {
			return piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusPropLinkToInvalid,
				ErrorContext: []string{"invalid token"},
			}
		}
	}

	// Verify linkby
	if pm.LinkBy != 0 {
		min := time.Now().Unix() + p.linkByPeriodMin()
		max := time.Now().Unix() + p.linkByPeriodMax()
		switch {
		case pm.LinkBy < min:
			e := fmt.Sprintf("linkby %v is less than min required of %v",
				pm.LinkBy, min)
			return piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		case pm.LinkBy > max:
			e := fmt.Sprintf("linkby %v is more than max allowed of %v",
				pm.LinkBy, max)
			return piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

func (p *politeiawww) verifyProposal(files []piv1.File, metadata []piv1.Metadata, publicKey, signature string) (*piv1.ProposalMetadata, error) {
	if len(files) == 0 {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusFileCountInvalid,
			ErrorContext: []string{"no files found"},
		}
	}

	// Verify the files adhere to all policy requirements
	var (
		countTextFiles  int
		countImageFiles int
		foundIndexFile  bool
	)
	filenames := make(map[string]struct{}, len(files))
	for _, v := range files {
		// Validate file name
		_, ok := filenames[v.Name]
		if ok {
			e := fmt.Sprintf("duplicate name %v", v.Name)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileNameInvalid,
				ErrorContext: []string{e},
			}
		}
		filenames[v.Name] = struct{}{}

		// Validate file payload
		if v.Payload == "" {
			e := fmt.Sprintf("file %v empty payload", v.Name)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}
		payloadb, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			e := fmt.Sprintf("file %v invalid base64", v.Name)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}

		// Verify computed file digest matches given file digest
		digest := util.Digest(payloadb)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileDigestInvalid,
				ErrorContext: []string{v.Name},
			}
		}
		if !bytes.Equal(digest, d[:]) {
			e := fmt.Sprintf("file %v digest got %v, want %x",
				v.Name, v.Digest, digest)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileDigestInvalid,
				ErrorContext: []string{e},
			}
		}

		// Verify detected MIME type matches given mime type
		ct := http.DetectContentType(payloadb)
		mimePayload, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return nil, err
		}
		mimeFile, _, err := mime.ParseMediaType(v.MIME)
		if err != nil {
			e := fmt.Sprintf("file %v mime '%v' not parsable", v.Name, v.MIME)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{e},
			}
		}
		if mimeFile != mimePayload {
			e := fmt.Sprintf("file %v mime got %v, want %v",
				v.Name, mimeFile, mimePayload)
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{e},
			}
		}

		// Run MIME type specific validation
		switch mimeFile {
		case mimeTypeText:
			countTextFiles++

			// Verify text file size
			if len(payloadb) > www.PolicyMaxMDSize {
				e := fmt.Sprintf("file %v size %v exceeds max size %v",
					v.Name, len(payloadb), www.PolicyMaxMDSize)
				return nil, piv1.UserErrorReply{
					ErrorCode:    piv1.ErrorStatusIndexFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

			// The only text file that is allowed is the index markdown
			// file.
			if v.Name != www.PolicyIndexFilename {
				e := fmt.Sprintf("want %v, got %v", www.PolicyIndexFilename, v.Name)
				return nil, piv1.UserErrorReply{
					ErrorCode:    piv1.ErrorStatusIndexFileNameInvalid,
					ErrorContext: []string{e},
				}
			}
			if foundIndexFile {
				e := fmt.Sprintf("more than one %v file found",
					www.PolicyIndexFilename)
				return nil, piv1.UserErrorReply{
					ErrorCode:    piv1.ErrorStatusIndexFileCountInvalid,
					ErrorContext: []string{e},
				}
			}

			// Set index file as being found
			foundIndexFile = true

		case mimeTypePNG:
			countImageFiles++

			// Verify image file size
			if len(payloadb) > www.PolicyMaxImageSize {
				e := fmt.Sprintf("image %v size %v exceeds max size %v",
					v.Name, len(payloadb), www.PolicyMaxImageSize)
				return nil, piv1.UserErrorReply{
					ErrorCode:    piv1.ErrorStatusImageFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

		default:
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{v.MIME},
			}
		}
	}

	// Verify that an index file is present
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFilename)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusIndexFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify file counts are acceptable
	if countTextFiles > www.PolicyMaxMDs {
		e := fmt.Sprintf("got %v text files, max is %v",
			countTextFiles, www.PolicyMaxMDs)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusTextFileCountInvalid,
			ErrorContext: []string{e},
		}
	}
	if countImageFiles > www.PolicyMaxImages {
		e := fmt.Sprintf("got %v image files, max is %v",
			countImageFiles, www.PolicyMaxImages)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusImageFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify that the metadata contains a ProposalMetadata and only
	// a ProposalMetadata.
	switch {
	case len(metadata) == 0:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropMetadataNotFound,
		}
	case len(metadata) > 1:
		e := fmt.Sprintf("metadata should only contain %v",
			www.HintProposalMetadata)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusMetadataCountInvalid,
			ErrorContext: []string{e},
		}
	}
	md := metadata[0]
	if md.Hint != www.HintProposalMetadata {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropMetadataNotFound,
		}
	}

	// Verify metadata fields
	b, err := base64.StdEncoding.DecodeString(md.Payload)
	if err != nil {
		e := fmt.Sprintf("metadata with hint %v invalid base64 payload", md.Hint)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusMetadataPayloadInvalid,
			ErrorContext: []string{e},
		}
	}
	digest := util.Digest(b)
	if md.Digest != hex.EncodeToString(digest) {
		e := fmt.Sprintf("metadata with hint %v got digest %v, want %v",
			md.Hint, md.Digest, hex.EncodeToString(digest))
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusMetadataDigestInvalid,
			ErrorContext: []string{e},
		}
	}

	// Decode ProposalMetadata
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var pm piv1.ProposalMetadata
	err = d.Decode(&pm)
	if err != nil {
		e := fmt.Sprintf("unable to decode %v payload", md.Hint)
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusMetadataPayloadInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify ProposalMetadata
	err = p.verifyProposalMetadata(pm)
	if err != nil {
		return nil, err
	}

	// Verify signature
	mr, err := wwwutil.MerkleRoot(files, metadata)
	if err != nil {
		return nil, err
	}
	err = util.VerifySignature(signature, publicKey, mr)
	if err != nil {
		return nil, convertUserErrorFromSignatureError(err)
	}

	return &pm, nil
}

func (p *politeiawww) processProposalNew(ctx context.Context, pn piv1.ProposalNew, usr user.User) (*piv1.ProposalNewReply, error) {
	log.Tracef("processProposalNew: %v", usr.Username)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user has a proposal credit
	if !p.userHasProposalCredits(usr) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusUserBalanceInsufficient,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != pn.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Verify proposal
	pm, err := p.verifyProposal(pn.Files, pn.Metadata,
		pn.PublicKey, pn.Signature)
	if err != nil {
		return nil, err
	}

	// Setup politeiad files. The Metadata objects are converted to
	// politeiad files since they contain user defined data that needs
	// to be included in the merkle root that politeiad signs.
	files := convertFilesFromPi(pn.Files)
	for _, v := range pn.Metadata {
		switch v.Hint {
		case piv1.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup metadata stream
	timestamp := time.Now().Unix()
	gm := pi.GeneralMetadata{
		UserID:    usr.ID.String(),
		PublicKey: pn.PublicKey,
		Signature: pn.Signature,
		Timestamp: timestamp,
	}
	b, err := pi.EncodeGeneralMetadata(gm)
	if err != nil {
		return nil, err
	}
	metadata := []pdv1.MetadataStream{
		{
			ID:      pi.MDStreamIDGeneralMetadata,
			Payload: string(b),
		},
	}

	// Send politeiad request
	dcr, err := p.newRecord(ctx, metadata, files)
	if err != nil {
		return nil, err
	}
	cr := convertCensorshipRecordFromPD(*dcr)

	// Deduct proposal credit from author's account
	err = p.spendProposalCredit(&usr, cr.Token)
	if err != nil {
		return nil, err
	}

	// Emit a new proposal event
	p.eventManager.emit(eventProposalSubmitted,
		dataProposalSubmitted{
			token:    cr.Token,
			name:     pm.Name,
			username: usr.Username,
		})

	log.Infof("Proposal submitted: %v %v", cr.Token, pm.Name)
	for k, f := range pn.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Get full proposal record
	pr, err := p.proposalRecordLatest(ctx, piv1.PropStateUnvetted, cr.Token)
	if err != nil {
		return nil, err
	}

	return &piv1.ProposalNewReply{
		Proposal: *pr,
	}, nil
}

// filenameIsMetadata returns whether the politeiad filename represents a pi
// Metadata object. These are provided as user defined metadata in proposal
// submissions but are stored as files in politeiad since they are part of the
// merkle root that the user signs and must also be part of the merkle root
// that politeiad signs.
func filenameIsMetadata(filename string) bool {
	switch filename {
	case pi.FileNameProposalMetadata:
		return true
	}
	return false
}

// filesToDel returns the names of the files that are included in current but
// are not included in updated. These are the files that need to be deleted
// from a proposal on update.
func filesToDel(current []piv1.File, updated []piv1.File) []string {
	curr := make(map[string]struct{}, len(current)) // [name]struct
	for _, v := range updated {
		curr[v.Name] = struct{}{}
	}

	del := make([]string, 0, len(current))
	for _, v := range current {
		_, ok := curr[v.Name]
		if !ok {
			del = append(del, v.Name)
		}
	}

	return del
}

func (p *politeiawww) processProposalEdit(ctx context.Context, pe piv1.ProposalEdit, usr user.User) (*piv1.ProposalEditReply, error) {
	log.Tracef("processProposalEdit: %v", pe.Token)

	// Verify token
	if !tokenIsFullLength(pe.Token) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropTokenInvalid,
		}
	}

	// Verify state
	switch pe.State {
	case piv1.PropStateUnvetted, piv1.PropStateVetted:
		// Allowed; continue
	default:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropStateInvalid,
		}
	}

	// Verify proposal
	pm, err := p.verifyProposal(pe.Files, pe.Metadata,
		pe.PublicKey, pe.Signature)
	if err != nil {
		return nil, err
	}

	// Verify user signed using active identity
	if usr.PublicKey() != pe.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Get the current proposal
	curr, err := p.proposalRecordLatest(ctx, pe.State, pe.Token)
	if err != nil {
		if errors.Is(err, errProposalNotFound) {
			return nil, piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusPropNotFound,
			}
		}
		return nil, err
	}

	// Verify the user is the author. The public keys are not static
	// values so the user IDs must be compared directly.
	if curr.UserID != usr.ID.String() {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusUnauthorized,
			ErrorContext: []string{"user is not author"},
		}
	}

	// Verify proposal status
	switch curr.Status {
	case piv1.PropStatusUnreviewed, piv1.PropStatusPublic:
		// Allowed; continue
	default:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropStatusInvalid,
		}
	}

	// Verification that requires plugin data or querying additional
	// proposal data is done in the politeiad pi plugin hook. This
	// includes:
	// -Verify linkto
	// -Verify vote status

	// Setup politeiad files. The Metadata objects are converted to
	// politeiad files since they contain user defined data that needs
	// to be included in the merkle root that politeiad signs.
	filesAdd := convertFilesFromPi(pe.Files)
	for _, v := range pe.Metadata {
		switch v.Hint {
		case piv1.HintProposalMetadata:
			filesAdd = append(filesAdd, convertFileFromMetadata(v))
		}
	}
	filesDel := filesToDel(curr.Files, pe.Files)

	// Setup politeiad metadata
	timestamp := time.Now().Unix()
	gm := pi.GeneralMetadata{
		UserID:    usr.ID.String(),
		PublicKey: pe.PublicKey,
		Signature: pe.Signature,
		Timestamp: timestamp,
	}
	b, err := pi.EncodeGeneralMetadata(gm)
	if err != nil {
		return nil, err
	}
	mdOverwrite := []pdv1.MetadataStream{
		{
			ID:      pi.MDStreamIDGeneralMetadata,
			Payload: string(b),
		},
	}
	mdAppend := []pdv1.MetadataStream{}

	// Send politeiad request
	// TODO verify that this will throw an error if no proposal files
	// were changed.
	var r *pdv1.Record
	switch pe.State {
	case piv1.PropStateUnvetted:
		r, err = p.updateUnvetted(ctx, pe.Token, mdAppend, mdOverwrite,
			filesAdd, filesDel)
		if err != nil {
			return nil, err
		}
	case piv1.PropStateVetted:
		r, err = p.updateVetted(ctx, pe.Token, mdAppend, mdOverwrite,
			filesAdd, filesDel)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown state %v", pe.State)
	}

	// Emit an edit proposal event
	p.eventManager.emit(eventProposalEdited, dataProposalEdited{
		userID:   usr.ID.String(),
		username: usr.Username,
		token:    pe.Token,
		name:     pm.Name,
		version:  r.Version,
	})

	log.Infof("Proposal edited: %v %v", pe.Token, pm.Name)
	for k, f := range pe.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Get updated proposal
	pr, err := p.proposalRecordLatest(ctx, pe.State, pe.Token)
	if err != nil {
		return nil, err
	}

	return &piv1.ProposalEditReply{
		Proposal: *pr,
	}, nil
}

func (p *politeiawww) processProposalSetStatus(ctx context.Context, pss piv1.ProposalSetStatus, usr user.User) (*piv1.ProposalSetStatusReply, error) {
	log.Tracef("processProposalSetStatus: %v %v", pss.Token, pss.Status)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify token
	if !tokenIsFullLength(pss.Token) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropTokenInvalid,
		}
	}

	// Verify state
	switch pss.State {
	case piv1.PropStateUnvetted, piv1.PropStateVetted:
		// Allowed; continue
	default:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropStateInvalid,
		}
	}

	// Verify reason
	_, required := statusReasonRequired[pss.Status]
	if required && pss.Reason == "" {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPropStatusChangeReasonInvalid,
			ErrorContext: []string{"reason not given"},
		}
	}

	// Verify user is an admin
	if !usr.Admin {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusUnauthorized,
			ErrorContext: []string{"user is not an admin"},
		}
	}

	// Verify user signed with their active identity
	if usr.PublicKey() != pss.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Verify signature
	msg := pss.Token + pss.Version + strconv.Itoa(int(pss.Status)) + pss.Reason
	err := util.VerifySignature(pss.Signature, pss.PublicKey, msg)
	if err != nil {
		return nil, convertUserErrorFromSignatureError(err)
	}

	// TODO don't allow censoring a proposal once the vote has started
	// Verification that requires retrieving the existing proposal is
	// done in politeiad. This includes:
	// -Verify proposal exists (politeiad)
	// -Verify proposal state is correct (politeiad)
	// -Verify version is the latest version (pi plugin)
	// -Verify status change is allowed (pi plugin)

	// Setup metadata
	timestamp := time.Now().Unix()
	sc := pi.StatusChange{
		Token:     pss.Token,
		Version:   pss.Version,
		Status:    pi.PropStatusT(pss.Status),
		Reason:    pss.Reason,
		PublicKey: pss.PublicKey,
		Signature: pss.Signature,
		Timestamp: timestamp,
	}
	b, err := pi.EncodeStatusChange(sc)
	if err != nil {
		return nil, err
	}
	mdAppend := []pdv1.MetadataStream{
		{
			ID:      pi.MDStreamIDStatusChanges,
			Payload: string(b),
		},
	}
	mdOverwrite := []pdv1.MetadataStream{}

	// Send politeiad request
	var r *pdv1.Record
	status := convertRecordStatusFromPropStatus(pss.Status)
	switch pss.State {
	case piv1.PropStateUnvetted:
		r, err = p.setUnvettedStatus(ctx, pss.Token, status, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	case piv1.PropStateVetted:
		r, err = p.setVettedStatus(ctx, pss.Token, status, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	}

	// The proposal state will have changed if the proposal was made
	// public.
	state := pss.State
	if pss.Status == piv1.PropStatusPublic {
		state = piv1.PropStateVetted
	}

	// Emit status change event
	p.eventManager.emit(eventProposalStatusChange,
		dataProposalStatusChange{
			token:   pss.Token,
			state:   state,
			status:  convertPropStatusFromPD(r.Status),
			version: r.Version,
			reason:  pss.Reason,
			adminID: usr.ID.String(),
		})

	// Get updated proposal
	pr, err := p.proposalRecordLatest(ctx, state, pss.Token)
	if err != nil {
		return nil, err
	}

	return &piv1.ProposalSetStatusReply{
		Proposal: *pr,
	}, nil
}

func (p *politeiawww) processProposals(ctx context.Context, ps piv1.Proposals, isAdmin bool) (*piv1.ProposalsReply, error) {
	log.Tracef("processProposals: %v", ps.Requests)

	// Verify state
	switch ps.State {
	case piv1.PropStateUnvetted, piv1.PropStateVetted:
		// Allowed; continue
	default:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusPropStateInvalid,
		}
	}

	// Get proposal records
	props, err := p.proposalRecords(ctx, ps.State, ps.Requests, ps.IncludeFiles)
	if err != nil {
		return nil, err
	}

	// Only admins are allowed to retrieve unvetted proposal files.
	// Remove all unvetted proposal files and user defined metadata if
	// the user is not an admin.
	if !isAdmin {
		for k, v := range props {
			if v.State == piv1.PropStateVetted {
				continue
			}
			v.Files = []piv1.File{}
			v.Metadata = []piv1.Metadata{}
			props[k] = v
		}
	}

	return &piv1.ProposalsReply{
		Proposals: props,
	}, nil
}

func (p *politeiawww) processProposalInventory(ctx context.Context, inv piv1.ProposalInventory, u *user.User) (*piv1.ProposalInventoryReply, error) {
	log.Tracef("processProposalInventory: %v", inv.UserID)

	// Send plugin command
	i := pi.ProposalInv{
		UserID: inv.UserID,
	}
	pir, err := p.proposalInv(ctx, i)
	if err != nil {
		return nil, err
	}

	// Determine if unvetted tokens should be returned
	switch {
	case u == nil:
		// No user session. Remove unvetted.
		pir.Unvetted = nil
	case u.Admin:
		// User is an admin. Return unvetted.
	case inv.UserID == u.ID.String():
		// User is requesting their own proposals. Return unvetted.
	default:
		// Remove unvetted for all other cases
		pir.Unvetted = nil
	}

	return &piv1.ProposalInventoryReply{
		Unvetted: pir.Unvetted,
		Vetted:   pir.Vetted,
	}, nil
}

func (p *politeiawww) processCommentNew(ctx context.Context, cn piv1.CommentNew, usr user.User) (*piv1.CommentNewReply, error) {
	log.Tracef("processCommentNew: %v", usr.Username)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != cn.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Only admins and the proposal author are allowed to comment on
	// unvetted proposals.
	if cn.State == piv1.PropStateUnvetted && !usr.Admin {
		// Fetch the proposal so we can see who the author is
		pr, err := p.proposalRecordLatest(ctx, cn.State, cn.Token)
		if err != nil {
			if errors.Is(err, errProposalNotFound) {
				return nil, piv1.UserErrorReply{
					ErrorCode: piv1.ErrorStatusPropNotFound,
				}
			}
			return nil, fmt.Errorf("proposalRecordLatest: %v", err)
		}
		if usr.ID.String() != pr.UserID {
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusUnauthorized,
				ErrorContext: []string{"user is not author or admin"},
			}
		}
	}

	// Send plugin command
	n := comments.New{
		UserID:    usr.ID.String(),
		State:     convertCommentStateFromPi(cn.State),
		Token:     cn.Token,
		ParentID:  cn.ParentID,
		Comment:   cn.Comment,
		PublicKey: cn.PublicKey,
		Signature: cn.Signature,
	}
	b, err := comments.EncodeNew(n)
	if err != nil {
		return nil, err
	}
	pt := pi.PassThrough{
		PluginID:  comments.ID,
		PluginCmd: comments.CmdNew,
		Payload:   string(b),
	}
	ptr, err := p.piPassThrough(ctx, pt)
	if err != nil {
		return nil, err
	}
	nr, err := comments.DecodeNewReply([]byte(ptr.Payload))
	if err != nil {
		return nil, err
	}

	// Prepare reply
	c := convertCommentFromPlugin(nr.Comment)
	c = commentFillInUser(c, usr)

	// Emit event
	p.eventManager.emit(eventProposalComment,
		dataProposalComment{
			state:     c.State,
			token:     c.Token,
			commentID: c.CommentID,
			parentID:  c.ParentID,
			username:  c.Username,
		})

	return &piv1.CommentNewReply{
		Comment: c,
	}, nil
}

func (p *politeiawww) processCommentVote(ctx context.Context, cv piv1.CommentVote, usr user.User) (*piv1.CommentVoteReply, error) {
	log.Tracef("processCommentVote: %v %v %v", cv.Token, cv.CommentID, cv.Vote)

	// Verify state
	if cv.State != piv1.PropStateVetted {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPropStateInvalid,
			ErrorContext: []string{"proposal must be vetted"},
		}
	}

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != cv.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	v := comments.Vote{
		UserID:    usr.ID.String(),
		State:     convertCommentStateFromPi(cv.State),
		Token:     cv.Token,
		CommentID: cv.CommentID,
		Vote:      convertCommentVoteFromPi(cv.Vote),
		PublicKey: cv.PublicKey,
		Signature: cv.Signature,
	}
	b, err := comments.EncodeVote(v)
	if err != nil {
		return nil, err
	}
	pt := pi.PassThrough{
		PluginID:  comments.ID,
		PluginCmd: comments.CmdVote,
		Payload:   string(b),
	}
	ptr, err := p.piPassThrough(ctx, pt)
	if err != nil {
		return nil, err
	}
	vr, err := comments.DecodeVoteReply([]byte(ptr.Payload))
	if err != nil {
		return nil, err
	}

	return &piv1.CommentVoteReply{
		Downvotes: vr.Downvotes,
		Upvotes:   vr.Upvotes,
		Timestamp: vr.Timestamp,
		Receipt:   vr.Receipt,
	}, nil
}

func (p *politeiawww) processCommentCensor(ctx context.Context, cc piv1.CommentCensor, usr user.User) (*piv1.CommentCensorReply, error) {
	log.Tracef("processCommentCensor: %v %v", cc.Token, cc.CommentID)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify user signed with their active identity
	if usr.PublicKey() != cc.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	d := comments.Del{
		State:     convertCommentStateFromPi(cc.State),
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,
	}
	b, err := comments.EncodeDel(d)
	if err != nil {
		return nil, err
	}
	pt := pi.PassThrough{
		PluginID:  comments.ID,
		PluginCmd: comments.CmdDel,
		Payload:   string(b),
	}
	ptr, err := p.piPassThrough(ctx, pt)
	if err != nil {
		return nil, err
	}
	dr, err := comments.DecodeDelReply([]byte(ptr.Payload))
	if err != nil {
		return nil, err
	}

	// Prepare reply
	c := convertCommentFromPlugin(dr.Comment)
	c = commentFillInUser(c, usr)

	return &piv1.CommentCensorReply{
		Comment: c,
	}, nil
}

func (p *politeiawww) processComments(ctx context.Context, c piv1.Comments, usr *user.User) (*piv1.CommentsReply, error) {
	log.Tracef("processComments: %v", c.Token)

	// Only admins and the proposal author are allowed to retrieve
	// unvetted comments. This is a public route so a user might not
	// exist.
	if c.State == piv1.PropStateUnvetted {
		var isAllowed bool
		switch {
		case usr == nil:
		// No logged in user. Unvetted not allowed.
		case usr.Admin:
			// User is an admin. Unvetted is allowed.
			isAllowed = true
		default:
			// Logged in user is not an admin. Check if they are the
			// proposal author.
			pr, err := p.proposalRecordLatest(ctx, c.State, c.Token)
			if err != nil {
				if errors.Is(err, errProposalNotFound) {
					return nil, piv1.UserErrorReply{
						ErrorCode: piv1.ErrorStatusPropNotFound,
					}
				}
				return nil, fmt.Errorf("proposalRecordLatest: %v", err)
			}
			if usr.ID.String() == pr.UserID {
				// User is the proposal author. Unvetted is allowed.
				isAllowed = true
			}
		}
		if !isAllowed {
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusUnauthorized,
				ErrorContext: []string{"user is not author or admin"},
			}
		}
	}

	// Send plugin command
	reply, err := p.commentsAll(ctx, comments.GetAll{
		State: convertCommentsStateFromPi(c.State),
		Token: c.Token,
	})
	if err != nil {
		return nil, err
	}

	// Prepare reply. Comments contain user data that needs to be
	// pulled from the user database.
	cs := make([]piv1.Comment, 0, len(reply.Comments))
	for _, cm := range reply.Comments {
		// Convert comment
		pic := convertCommentFromPlugin(cm)

		// Get comment user data
		uuid, err := uuid.Parse(cm.UserID)
		if err != nil {
			return nil, err
		}
		u, err := p.db.UserGetById(uuid)
		if err != nil {
			return nil, err
		}
		pic.Username = u.Username

		// Add comment
		cs = append(cs, pic)
	}

	return &piv1.CommentsReply{
		Comments: cs,
	}, nil
}

func (p *politeiawww) processCommentVotes(ctx context.Context, cv piv1.CommentVotes) (*piv1.CommentVotesReply, error) {
	log.Tracef("processCommentVotes: %v %v", cv.Token, cv.UserID)

	// Verify state
	if cv.State != piv1.PropStateVetted {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPropStateInvalid,
			ErrorContext: []string{"proposal must be vetted"},
		}
	}

	// Send plugin command
	v := comments.Votes{
		State:  convertCommentsStateFromPi(cv.State),
		Token:  cv.Token,
		UserID: cv.UserID,
	}
	cvr, err := p.commentVotes(ctx, v)
	if err != nil {
		return nil, err
	}

	return &piv1.CommentVotesReply{
		Votes: convertCommentVoteDetailsFromPlugin(cvr.Votes),
	}, nil
}

func (p *politeiawww) processVoteAuthorize(ctx context.Context, va piv1.VoteAuthorize, usr user.User) (*piv1.VoteAuthorizeReply, error) {
	log.Tracef("processVoteAuthorize: %v", va.Token)

	// Verify user signed with their active identity
	if usr.PublicKey() != va.PublicKey {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// TODO Verify user is the proposal author. Hmmm I think the userID
	// probably needs to be attached to the vote authorization.

	// Send plugin command
	ar, err := p.voteAuthorize(ctx, convertVoteAuthorizeFromPi(va))
	if err != nil {
		return nil, err
	}

	// TODO Emit notification

	return &piv1.VoteAuthorizeReply{
		Timestamp: ar.Timestamp,
		Receipt:   ar.Receipt,
	}, nil
}

func (p *politeiawww) processVoteStart(ctx context.Context, vs piv1.VoteStart, usr user.User) (*piv1.VoteStartReply, error) {
	log.Tracef("processVoteStart: %v", len(vs.Starts))

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify there is work to be done
	if len(vs.Starts) == 0 {
		return nil, piv1.UserErrorReply{
			ErrorCode:    piv1.ErrorStatusStartDetailsInvalid,
			ErrorContext: []string{"no start details found"},
		}
	}

	// Verify admin signed with their active identity
	for _, v := range vs.Starts {
		if usr.PublicKey() != v.PublicKey {
			return nil, piv1.UserErrorReply{
				ErrorCode:    piv1.ErrorStatusPublicKeyInvalid,
				ErrorContext: []string{"not active identity"},
			}
		}
	}

	// Start vote
	var (
		sr  *ticketvote.StartReply
		err error
	)
	switch vs.Starts[0].Params.Type {
	case piv1.VoteTypeStandard:
		// A standard vote can be started using the ticketvote plugin
		// directly.
		sr, err = p.voteStart(ctx, convertVoteStartFromPi(vs))
		if err != nil {
			return nil, err
		}

	case piv1.VoteTypeRunoff:
		// A runoff vote requires additional validation that is not part
		// of the ticketvote plugin. We pass the ticketvote command
		// through the pi plugin so that it can perform this additional
		// validation.
		s := convertVoteStartFromPi(vs)
		payload, err := ticketvote.EncodeStart(s)
		if err != nil {
			return nil, err
		}
		pt := pi.PassThrough{
			PluginID:  ticketvote.ID,
			PluginCmd: ticketvote.CmdStart,
			Payload:   string(payload),
		}
		ptr, err := p.piPassThrough(ctx, pt)
		if err != nil {
			return nil, err
		}
		sr, err = ticketvote.DecodeStartReply([]byte(ptr.Payload))
		if err != nil {
			return nil, err
		}

	default:
		return nil, piv1.UserErrorReply{
			ErrorCode: piv1.ErrorStatusVoteTypeInvalid,
		}
	}

	// TODO Emit notification for each start

	return &piv1.VoteStartReply{
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}, nil
}

func (p *politeiawww) processCastBallot(ctx context.Context, vc piv1.CastBallot) (*piv1.CastBallotReply, error) {
	log.Tracef("processCastBallot")

	cb := ticketvote.CastBallot{
		Ballot: convertCastVotesFromPi(vc.Votes),
	}
	reply, err := p.castBallot(ctx, cb)
	if err != nil {
		return nil, err
	}

	return &piv1.CastBallotReply{
		Receipts: convertCastVoteRepliesFromPlugin(reply.Receipts),
	}, nil
}

func (p *politeiawww) processVotes(ctx context.Context, v piv1.Votes) (*piv1.VotesReply, error) {
	log.Tracef("processVotes: %v", v.Tokens)

	vd, err := p.voteDetails(ctx, v.Tokens)
	if err != nil {
		return nil, err
	}

	return &piv1.VotesReply{
		Votes: convertProposalVotesFromPlugin(vd.Votes),
	}, nil
}

func (p *politeiawww) processVoteResults(ctx context.Context, vr piv1.VoteResults) (*piv1.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", vr.Token)

	cvr, err := p.voteResults(ctx, vr.Token)
	if err != nil {
		return nil, err
	}

	return &piv1.VoteResultsReply{
		Votes: convertCastVoteDetailsFromPlugin(cvr.Votes),
	}, nil
}

func (p *politeiawww) processVoteSummaries(ctx context.Context, vs piv1.VoteSummaries) (*piv1.VoteSummariesReply, error) {
	log.Tracef("processVoteSummaries: %v", vs.Tokens)

	r, err := p.voteSummaries(ctx, vs.Tokens)
	if err != nil {
		return nil, err
	}

	return &piv1.VoteSummariesReply{
		Summaries: convertVoteSummariesFromPlugin(r.Summaries),
		BestBlock: r.BestBlock,
	}, nil
}

func (p *politeiawww) processVoteInventory(ctx context.Context) (*piv1.VoteInventoryReply, error) {
	log.Tracef("processVoteInventory")

	r, err := p.piVoteInventory(ctx)
	if err != nil {
		return nil, err
	}

	return &piv1.VoteInventoryReply{
		Unauthorized: r.Unauthorized,
		Authorized:   r.Authorized,
		Started:      r.Started,
		Approved:     r.Approved,
		Rejected:     r.Rejected,
		BestBlock:    r.BestBlock,
	}, nil
}

func (p *politeiawww) handleProposalNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalNew")

	var pn piv1.ProposalNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pn); err != nil {
		respondWithPiError(w, r, "handleProposalNew: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalNew: getSessionUser: %v", err)
		return
	}

	pnr, err := p.processProposalNew(r.Context(), pn, *user)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalNew: processProposalNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pnr)
}

func (p *politeiawww) handleProposalEdit(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalEdit")

	var pe piv1.ProposalEdit
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pe); err != nil {
		respondWithPiError(w, r, "handleProposalEdit: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalEdit: getSessionUser: %v", err)
		return
	}

	per, err := p.processProposalEdit(r.Context(), pe, *user)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalEdit: processProposalEdit: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, per)
}

func (p *politeiawww) handleProposalSetStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalSetStatus")

	var pss piv1.ProposalSetStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pss); err != nil {
		respondWithPiError(w, r, "handleProposalSetStatus: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalSetStatus: getSessionUser: %v", err)
		return
	}

	pssr, err := p.processProposalSetStatus(r.Context(), pss, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalSetStatus: processProposalSetStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pssr)
}

func (p *politeiawww) handleProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposals")

	var ps piv1.Proposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ps); err != nil {
		respondWithPiError(w, r, "handleProposals: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposals: getSessionUser: %v", err)
		return
	}

	isAdmin := usr != nil && usr.Admin
	ppi, err := p.processProposals(r.Context(), ps, isAdmin)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposals: processProposals: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ppi)
}

func (p *politeiawww) handleProposalInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalInventory")

	var inv piv1.ProposalInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&inv); err != nil {
		respondWithPiError(w, r, "handleProposalInventory: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposalInventory: getSessionUser: %v", err)
		return
	}

	pir, err := p.processProposalInventory(r.Context(), inv, usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalInventory: processProposalInventory: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pir)
}

func (p *politeiawww) handleCommentNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentNew")

	var cn piv1.CommentNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cn); err != nil {
		respondWithPiError(w, r, "handleCommentNew: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: getSessionUser: %v", err)
		return
	}

	cnr, err := p.processCommentNew(r.Context(), cn, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: processCommentNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cnr)
}

func (p *politeiawww) handleCommentVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVote")

	var cv piv1.CommentVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		respondWithPiError(w, r, "handleCommentVote: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: getSessionUser: %v", err)
		return
	}

	vcr, err := p.processCommentVote(r.Context(), cv, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processCommentVote: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vcr)
}

func (p *politeiawww) handleCommentCensor(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentCensor")

	var cc piv1.CommentCensor
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cc); err != nil {
		respondWithPiError(w, r, "handleCommentCensor: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentCensor: getSessionUser: %v", err)
		return
	}

	ccr, err := p.processCommentCensor(r.Context(), cc, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentCensor: processCommentCensor: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ccr)
}

func (p *politeiawww) handleComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleComments")

	var c piv1.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithPiError(w, r, "handleComments: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposalInventory: getSessionUser: %v", err)
		return
	}

	cr, err := p.processComments(r.Context(), c, usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processComments: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

func (p *politeiawww) handleCommentVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVotes")

	var cv piv1.CommentVotes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		respondWithPiError(w, r, "handleCommentVotes: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	cvr, err := p.processCommentVotes(r.Context(), cv)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVotes: processCommentVotes: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cvr)
}

func (p *politeiawww) handleVoteAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteAuthorize")

	var va piv1.VoteAuthorize
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&va); err != nil {
		respondWithPiError(w, r, "handleVoteAuthorize: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteAuthorize: getSessionUser: %v", err)
		return
	}

	vr, err := p.processVoteAuthorize(r.Context(), va, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteAuthorize: processVoteAuthorize: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleVoteStart(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteStart")

	var vs piv1.VoteStart
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "handleVoteStart: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStart: getSessionUser: %v", err)
		return
	}

	vsr, err := p.processVoteStart(r.Context(), vs, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStart: processVoteStart: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleCastBallot(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastBallot")

	var vb piv1.CastBallot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vb); err != nil {
		respondWithPiError(w, r, "handleCastBallot: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vbr, err := p.processCastBallot(r.Context(), vb)
	if err != nil {
		respondWithPiError(w, r,
			"handleCastBallot: processCastBallot: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vbr)
}

func (p *politeiawww) handleVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVotes")

	var v piv1.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithPiError(w, r, "handleVotes: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vr, err := p.processVotes(r.Context(), v)
	if err != nil {
		respondWithPiError(w, r,
			"handleVotes: processVotes: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	var vr piv1.VoteResults
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vr); err != nil {
		respondWithPiError(w, r, "handleVoteResults: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vrr, err := p.processVoteResults(r.Context(), vr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteResults: prcoessVoteResults: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

func (p *politeiawww) handleVoteSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteSummaries")

	var vs piv1.VoteSummaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vsr, err := p.processVoteSummaries(r.Context(), vs)
	if err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: processVoteSummaries: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleVoteInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteInventory")

	var vi piv1.VoteInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vi); err != nil {
		respondWithPiError(w, r, "handleVoteInventory: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vir, err := p.processVoteInventory(r.Context())
	if err != nil {
		respondWithPiError(w, r, "handleVoteInventory: processVoteInventory: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vir)
}

// setPiRoutes sets the pi API routes.
func (p *politeiawww) setPiRoutes() {
	// Proposal routes
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteProposalNew, p.handleProposalNew,
		permissionLogin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteProposalEdit, p.handleProposalEdit,
		permissionLogin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteProposalSetStatus, p.handleProposalSetStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteTimestamps, p.handleTimestamps,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteProposals, p.handleProposals,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteProposalInventory, p.handleProposalInventory,
		permissionPublic)

	// Comment routes
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteCommentNew, p.handleCommentNew,
		permissionLogin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteCommentVote, p.handleCommentVote,
		permissionLogin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteCommentCensor, p.handleCommentCensor,
		permissionAdmin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteComments, p.handleComments,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteCommentVotes, p.handleCommentVotes,
		permissionPublic)

	// Vote routes
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVoteAuthorize, p.handleVoteAuthorize,
		permissionLogin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVoteStart, p.handleVoteStart,
		permissionAdmin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteCastBallot, p.handleCastBallot,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVotes, p.handleVotes,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVoteResults, p.handleVoteResults,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVoteSummaries, p.handleVoteSummaries,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteVoteInventory, p.handleVoteInventory,
		permissionPublic)
}
