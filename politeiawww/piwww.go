// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
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

	"github.com/decred/politeia/plugins/comments"
	piplugin "github.com/decred/politeia/plugins/pi"
	"github.com/decred/politeia/plugins/ticketvote"
	pd "github.com/decred/politeia/politeiad/api/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// TODO use pi policies. Should the policies be defined in the pi plugin
// or the pi api spec?
// TODO ensure plugins can't write data using short proposal token.
// TODO move proposal validation to pi plugin
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
	statusReasonRequired = map[pi.PropStatusT]struct{}{
		pi.PropStatusCensored:  {},
		pi.PropStatusAbandoned: {},
	}

	// errProposalNotFound is emitted when a proposal is not found in
	// politeiad for a specified token and version.
	errProposalNotFound = errors.New("proposal not found")
)

// tokenIsValid returns whether the provided string is a valid politeiad
// censorship record token. This CAN BE EITHER the short token or the full
// length token.
//
// Short tokens should only be used when retrieving data. Data that is written
// to disk should always reference the full length token.
func tokenIsValid(token string) bool {
	// Verify token size
	switch {
	case len(token) == pd.TokenPrefixLength:
		// Token is a short proposal token
	case len(token) == pd.TokenSizeMin*2:
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
	if len(b) != pd.TokenSizeMin {
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
func proposalName(pr pi.ProposalRecord) string {
	var name string
	for _, v := range pr.Metadata {
		if v.Hint == pi.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			pm, err := piplugin.DecodeProposalMetadata(b)
			if err != nil {
				return ""
			}
			name = pm.Name
		}
	}
	return name
}

func convertUserErrorFromSignatureError(err error) pi.UserErrorReply {
	var e util.SignatureError
	var s pi.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = pi.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = pi.ErrorStatusSignatureInvalid
		}
	}
	return pi.UserErrorReply{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func convertPropStateFromPropStatus(s pi.PropStatusT) pi.PropStateT {
	switch s {
	case pi.PropStatusUnvetted, pi.PropStatusCensored:
		return pi.PropStateUnvetted
	case pi.PropStatusPublic, pi.PropStatusAbandoned:
		return pi.PropStateVetted
	}
	return pi.PropStateInvalid
}

func convertPropStateFromPi(s pi.PropStateT) piplugin.PropStateT {
	switch s {
	case pi.PropStateUnvetted:
		return piplugin.PropStateUnvetted
	case pi.PropStateVetted:
		return piplugin.PropStateVetted
	}
	return piplugin.PropStateInvalid
}

func convertRecordStatusFromPropStatus(s pi.PropStatusT) pd.RecordStatusT {
	switch s {
	case pi.PropStatusUnvetted:
		return pd.RecordStatusNotReviewed
	case pi.PropStatusPublic:
		return pd.RecordStatusPublic
	case pi.PropStatusCensored:
		return pd.RecordStatusCensored
	case pi.PropStatusAbandoned:
		return pd.RecordStatusArchived
	}
	return pd.RecordStatusInvalid
}

func convertFileFromMetadata(m pi.Metadata) pd.File {
	var name string
	switch m.Hint {
	case pi.HintProposalMetadata:
		name = piplugin.FileNameProposalMetadata
	}
	return pd.File{
		Name:    name,
		MIME:    mimeTypeTextUTF8,
		Digest:  m.Digest,
		Payload: m.Payload,
	}
}

func convertFileFromPi(f pi.File) pd.File {
	return pd.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertFilesFromPi(files []pi.File) []pd.File {
	f := make([]pd.File, 0, len(files))
	for _, v := range files {
		f = append(f, convertFileFromPi(v))
	}
	return f
}

func convertPropStatusFromPD(s pd.RecordStatusT) pi.PropStatusT {
	switch s {
	case pd.RecordStatusNotFound:
		// Intentionally omitted. No corresponding PropStatusT.
	case pd.RecordStatusNotReviewed:
		return pi.PropStatusUnvetted
	case pd.RecordStatusCensored:
		return pi.PropStatusCensored
	case pd.RecordStatusPublic:
		return pi.PropStatusPublic
	case pd.RecordStatusUnreviewedChanges:
		return pi.PropStatusUnvetted
	case pd.RecordStatusArchived:
		return pi.PropStatusAbandoned
	}
	return pi.PropStatusInvalid
}

func convertCensorshipRecordFromPD(cr pd.CensorshipRecord) pi.CensorshipRecord {
	return pi.CensorshipRecord{
		Token:     cr.Token,
		Merkle:    cr.Merkle,
		Signature: cr.Signature,
	}
}

func convertFilesFromPD(f []pd.File) ([]pi.File, []pi.Metadata) {
	files := make([]pi.File, 0, len(f))
	metadata := make([]pi.Metadata, 0, len(f))
	for _, v := range f {
		switch v.Name {
		case piplugin.FileNameProposalMetadata:
			metadata = append(metadata, pi.Metadata{
				Hint:    pi.HintProposalMetadata,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		default:
			files = append(files, pi.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		}
	}
	return files, metadata
}

func convertProposalRecordFromPD(r pd.Record) (*pi.ProposalRecord, error) {
	// Decode metadata streams
	var (
		pg  *piplugin.ProposalGeneral
		sc  = make([]piplugin.StatusChange, 0, 16)
		err error
	)
	for _, v := range r.Metadata {
		switch v.ID {
		case piplugin.MDStreamIDProposalGeneral:
			pg, err = piplugin.DecodeProposalGeneral([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		case piplugin.MDStreamIDStatusChanges:
			sc, err = piplugin.DecodeStatusChanges([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert to pi types
	files, metadata := convertFilesFromPD(r.Files)
	status := convertPropStatusFromPD(r.Status)
	state := convertPropStateFromPropStatus(status)

	statuses := make([]pi.StatusChange, 0, len(sc))
	for _, v := range sc {
		statuses = append(statuses, pi.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    pi.PropStatusT(v.Status),
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
	return &pi.ProposalRecord{
		Version:          r.Version,
		Timestamp:        pg.Timestamp,
		State:            state,
		Status:           status,
		UserID:           "", // Intentionally omitted
		Username:         "", // Intentionally omitted
		PublicKey:        pg.PublicKey,
		Signature:        pg.Signature,
		Comments:         0, // Intentionally omitted
		Statuses:         statuses,
		Files:            files,
		Metadata:         metadata,
		LinkedFrom:       []string{}, // Intentionally omitted
		CensorshipRecord: convertCensorshipRecordFromPD(r.CensorshipRecord),
	}, nil
}

func convertCommentsStateFromPi(s pi.PropStateT) comments.StateT {
	switch s {
	case pi.PropStateUnvetted:
		return comments.StateUnvetted
	case pi.PropStateVetted:
		return comments.StateVetted
	}
	return comments.StateInvalid
}

func convertPropStateFromComments(s comments.StateT) pi.PropStateT {
	switch s {
	case comments.StateUnvetted:
		return pi.PropStateUnvetted
	case comments.StateVetted:
		return pi.PropStateVetted
	}
	return pi.PropStateInvalid
}

func convertCommentFromPlugin(cm comments.Comment) pi.Comment {
	return pi.Comment{
		UserID:    cm.UserID,
		Username:  "", // Intentionally omitted, needs to be pulled from userdb
		State:     convertPropStateFromComments(cm.State),
		Token:     cm.Token,
		ParentID:  cm.ParentID,
		Comment:   cm.Comment,
		PublicKey: cm.PublicKey,
		Signature: cm.Signature,
		CommentID: cm.CommentID,
		Version:   cm.Version,
		Timestamp: cm.Timestamp,
		Receipt:   cm.Receipt,
		Score:     cm.Score,
		Deleted:   cm.Deleted,
		Reason:    cm.Reason,
	}
}

func convertCommentVoteFromPlugin(v comments.VoteT) pi.CommentVoteT {
	switch v {
	case comments.VoteDownvote:
		return pi.CommentVoteDownvote
	case comments.VoteUpvote:
		return pi.CommentVoteUpvote
	}
	return pi.CommentVoteInvalid
}

func convertCommentVoteDetailsFromPlugin(cv []comments.CommentVote) []pi.CommentVoteDetails {
	c := make([]pi.CommentVoteDetails, 0, len(cv))
	for _, v := range cv {
		c = append(c, pi.CommentVoteDetails{
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

func convertCommentVoteFromPi(v pi.CommentVoteT) piplugin.CommentVoteT {
	switch v {
	case pi.CommentVoteInvalid:
		return piplugin.VoteInvalid
	case pi.CommentVoteDownvote:
		return piplugin.VoteDownvote
	case pi.CommentVoteUpvote:
		return piplugin.VoteUpvote
	default:
		return piplugin.VoteInvalid
	}
}

func convertVoteAuthActionFromPi(a pi.VoteAuthActionT) ticketvote.AuthActionT {
	switch a {
	case pi.VoteAuthActionAuthorize:
		return ticketvote.ActionAuthorize
	case pi.VoteAuthActionRevoke:
		return ticketvote.ActionRevoke
	default:
		return ticketvote.ActionAuthorize
	}
}

func convertVoteAuthorizeFromPi(va pi.VoteAuthorize) ticketvote.Authorize {
	return ticketvote.Authorize{
		Token:     va.Token,
		Version:   va.Version,
		Action:    convertVoteAuthActionFromPi(va.Action),
		PublicKey: va.PublicKey,
		Signature: va.Signature,
	}
}

func convertVoteAuthsFromPi(auths []pi.VoteAuthorize) []ticketvote.Authorize {
	a := make([]ticketvote.Authorize, 0, len(auths))
	for _, v := range auths {
		a = append(a, convertVoteAuthorizeFromPi(v))
	}
	return a
}

func convertVoteTypeFromPi(t pi.VoteT) ticketvote.VoteT {
	switch t {
	case pi.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case pi.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	return ticketvote.VoteTypeInvalid
}

func convertVoteParamsFromPi(v pi.VoteParams) ticketvote.VoteParams {
	tv := ticketvote.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeFromPi(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
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

func convertVoteStartFromPi(vs pi.VoteStart) ticketvote.Start {
	return ticketvote.Start{
		Params:    convertVoteParamsFromPi(vs.Params),
		PublicKey: vs.PublicKey,
		Signature: vs.Signature,
	}
}

func convertVoteStartsFromPi(starts []pi.VoteStart) []ticketvote.Start {
	s := make([]ticketvote.Start, 0, len(starts))
	for _, v := range starts {
		s = append(s, convertVoteStartFromPi(v))
	}
	return s
}

func convertCastVotesFromPi(votes []pi.CastVote) []ticketvote.CastVote {
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

func convertVoteErrorFromPlugin(e ticketvote.VoteErrorT) pi.VoteErrorT {
	switch e {
	case ticketvote.VoteErrorInvalid:
		return pi.VoteErrorInvalid
	case ticketvote.VoteErrorInternalError:
		return pi.VoteErrorInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return pi.VoteErrorRecordNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return pi.VoteErrorVoteBitInvalid
	case ticketvote.VoteErrorVoteStatusInvalid:
		return pi.VoteErrorVoteStatusInvalid
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return pi.VoteErrorTicketAlreadyVoted
	case ticketvote.VoteErrorTicketNotEligible:
		return pi.VoteErrorTicketNotEligible
	default:
		return pi.VoteErrorInternalError
	}
}

func convertVoteTypeFromPlugin(t ticketvote.VoteT) pi.VoteT {
	switch t {
	case ticketvote.VoteTypeStandard:
		return pi.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return pi.VoteTypeRunoff
	}
	return pi.VoteTypeInvalid

}

func convertVoteParamsFromPlugin(v ticketvote.VoteParams) pi.VoteParams {
	vp := pi.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeFromPlugin(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
	}
	vo := make([]pi.VoteOption, 0, len(v.Options))
	for _, o := range v.Options {
		vo = append(vo, pi.VoteOption{
			ID:          o.ID,
			Description: o.Description,
			Bit:         o.Bit,
		})
	}
	vp.Options = vo

	return vp
}

func convertCastVoteRepliesFromPlugin(replies []ticketvote.CastVoteReply) []pi.CastVoteReply {
	r := make([]pi.CastVoteReply, 0, len(replies))
	for _, v := range replies {
		r = append(r, pi.CastVoteReply{
			Ticket:       v.Ticket,
			Receipt:      v.Receipt,
			ErrorCode:    convertVoteErrorFromPlugin(v.ErrorCode),
			ErrorContext: v.ErrorContext,
		})
	}
	return r
}

func convertVoteDetailsFromPlugin(vd ticketvote.VoteDetails) pi.VoteDetails {
	return pi.VoteDetails{
		Params:           convertVoteParamsFromPlugin(vd.Params),
		PublicKey:        vd.PublicKey,
		Signature:        vd.Signature,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}
}

func convertAuthorizeDetailsFromPlugin(auths []ticketvote.AuthorizeDetails) []pi.AuthorizeDetails {
	a := make([]pi.AuthorizeDetails, 0, len(auths))
	for _, v := range auths {
		a = append(a, pi.AuthorizeDetails{
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

func convertCastVoteDetailsFromPlugin(votes []ticketvote.CastVoteDetails) []pi.CastVoteDetails {
	vs := make([]pi.CastVoteDetails, 0, len(votes))
	for _, v := range votes {
		vs = append(vs, pi.CastVoteDetails{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   v.Receipt,
		})
	}
	return vs
}

func convertProposalVotesFromPlugin(votes map[string]ticketvote.RecordVote) map[string]pi.ProposalVote {
	pv := make(map[string]pi.ProposalVote, len(votes))
	for k, v := range votes {
		var vdp *pi.VoteDetails
		if v.Vote != nil {
			vd := convertVoteDetailsFromPlugin(*v.Vote)
			vdp = &vd
		}
		pv[k] = pi.ProposalVote{
			Auths: convertAuthorizeDetailsFromPlugin(v.Auths),
			Vote:  vdp,
		}
	}
	return pv
}

func convertVoteStatusFromPlugin(s ticketvote.VoteStatusT) pi.VoteStatusT {
	switch s {
	case ticketvote.VoteStatusInvalid:
		return pi.VoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return pi.VoteStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		return pi.VoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return pi.VoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return pi.VoteStatusFinished
	default:
		return pi.VoteStatusInvalid
	}
}

func convertVoteSummaryFromPlugin(s ticketvote.Summary) pi.VoteSummary {
	results := make([]pi.VoteResult, 0, len(s.Results))
	for _, v := range s.Results {
		results = append(results, pi.VoteResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.VoteBit,
			Votes:       v.Votes,
		})
	}
	return pi.VoteSummary{
		Type:             convertVoteTypeFromPlugin(s.Type),
		Status:           convertVoteStatusFromPlugin(s.Status),
		Duration:         s.Duration,
		StartBlockHeight: s.StartBlockHeight,
		StartBlockHash:   s.StartBlockHash,
		EndBlockHeight:   s.EndBlockHeight,
		EligibleTickets:  s.EligibleTickets,
		QuorumPercentage: s.QuorumPercentage,
		Results:          results,
		Approved:         s.Approved,
	}
}

func convertVoteSummariesFromPlugin(ts map[string]ticketvote.Summary) map[string]pi.VoteSummary {
	s := make(map[string]pi.VoteSummary, len(ts))
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
//
// TODO this presents a challenge because the proposal Metadata still needs to
// be returned even if the proposal Files are not returned, which means that we
// will always need to fetch the record from politeiad with the files attached
// since the proposal Metadata is saved to politeiad as a politeiad File.
func (p *politeiawww) proposalRecords(state pi.PropStateT, reqs []pi.ProposalRequest, includeFiles bool) (map[string]pi.ProposalRecord, error) {
	// Get politeiad records
	props := make([]pi.ProposalRecord, 0, len(reqs))
	for _, v := range reqs {
		var r *pd.Record
		var err error
		switch state {
		case pi.PropStateUnvetted:
			// Unvetted politeiad record
			r, err = p.getUnvetted(v.Token, v.Version)
			if err != nil {
				return nil, fmt.Errorf("getUnvetted %v: %v", v.Token, err)
			}
		case pi.PropStateVetted:
			// Vetted politeiad record
			r, err = p.getVetted(v.Token, v.Version)
			if err != nil {
				return nil, fmt.Errorf("getVetted %v: %v", v.Token, err)
			}
		default:
			return nil, fmt.Errorf("unknown state %v", state)
		}

		if r.Status == pd.RecordStatusNotFound {
			// Record wasn't found. Don't include token in the results.
			continue
		}

		pr, err := convertProposalRecordFromPD(*r)
		if err != nil {
			return nil, fmt.Errorf("convertProposalRecordFromPD %v: %v",
				v.Token, err)
		}

		// Remove files if specified. The Metadata objects will still be
		// returned.
		if !includeFiles {
			pr.Files = []pi.File{}
		}

		props = append(props, *pr)
	}

	// Verify we've got some results
	if len(props) == 0 {
		return map[string]pi.ProposalRecord{}, nil
	}

	// Get proposal plugin data
	tokens := make([]string, 0, len(props))
	for _, v := range props {
		tokens = append(tokens, v.CensorshipRecord.Token)
	}
	ps := piplugin.Proposals{
		State:  convertPropStateFromPi(state),
		Tokens: tokens,
	}
	psr, err := p.piProposals(ps)
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
		props[k].UserID = u.ID.String()
		props[k].Username = u.Username
	}

	// Convert proposals to a map
	proposals := make(map[string]pi.ProposalRecord, len(props))
	for _, v := range props {
		proposals[v.CensorshipRecord.Token] = v
	}

	return proposals, nil
}

// proposalRecord returns the proposal record for the provided token and
// version. A blank version will return the most recent version. A
// errProposalNotFound error will be returned if a proposal is not found for
// the provided token/version combination.
func (p *politeiawww) proposalRecord(state pi.PropStateT, token, version string) (*pi.ProposalRecord, error) {
	prs, err := p.proposalRecords(state, []pi.ProposalRequest{
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
func (p *politeiawww) proposalRecordLatest(state pi.PropStateT, token string) (*pi.ProposalRecord, error) {
	return p.proposalRecord(state, token, "")
}

func (p *politeiawww) verifyProposalMetadata(pm pi.ProposalMetadata) error {
	// Verify name
	if !proposalNameIsValid(pm.Name) {
		return pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPropNameInvalid,
			ErrorContext: []string{proposalNameRegex()},
		}
	}

	// Verify linkto
	if pm.LinkTo != "" {
		if !tokenIsFullLength(pm.LinkTo) {
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkToInvalid,
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
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		case pm.LinkBy > max:
			e := fmt.Sprintf("linkby %v is more than max allowed of %v",
				pm.LinkBy, max)
			return pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPropLinkByInvalid,
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

func (p *politeiawww) verifyProposal(files []pi.File, metadata []pi.Metadata, publicKey, signature string) (*pi.ProposalMetadata, error) {
	if len(files) == 0 {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusFileCountInvalid,
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
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileNameInvalid,
				ErrorContext: []string{e},
			}
		}
		filenames[v.Name] = struct{}{}

		// Validate file payload
		if v.Payload == "" {
			e := fmt.Sprintf("file %v empty payload", v.Name)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}
		payloadb, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			e := fmt.Sprintf("file %v invalid base64", v.Name)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFilePayloadInvalid,
				ErrorContext: []string{e},
			}
		}

		// Verify computed file digest matches given file digest
		digest := util.Digest(payloadb)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileDigestInvalid,
				ErrorContext: []string{v.Name},
			}
		}
		if !bytes.Equal(digest, d[:]) {
			e := fmt.Sprintf("file %v digest got %v, want %x",
				v.Name, v.Digest, digest)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileDigestInvalid,
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
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{e},
			}
		}
		if mimeFile != mimePayload {
			e := fmt.Sprintf("file %v mime got %v, want %v",
				v.Name, mimeFile, mimePayload)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
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
				return nil, pi.UserErrorReply{
					ErrorCode:    pi.ErrorStatusIndexFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

			// The only text file that is allowed is the index markdown
			// file.
			if v.Name != www.PolicyIndexFilename {
				e := fmt.Sprintf("want %v, got %v", www.PolicyIndexFilename, v.Name)
				return nil, pi.UserErrorReply{
					ErrorCode:    pi.ErrorStatusIndexFileNameInvalid,
					ErrorContext: []string{e},
				}
			}
			if foundIndexFile {
				e := fmt.Sprintf("more than one %v file found",
					www.PolicyIndexFilename)
				return nil, pi.UserErrorReply{
					ErrorCode:    pi.ErrorStatusIndexFileCountInvalid,
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
				return nil, pi.UserErrorReply{
					ErrorCode:    pi.ErrorStatusImageFileSizeInvalid,
					ErrorContext: []string{e},
				}
			}

		default:
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusFileMIMEInvalid,
				ErrorContext: []string{v.MIME},
			}
		}
	}

	// Verify that an index file is present
	if !foundIndexFile {
		e := fmt.Sprintf("%v file not found", www.PolicyIndexFilename)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusIndexFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify file counts are acceptable
	if countTextFiles > www.PolicyMaxMDs {
		e := fmt.Sprintf("got %v text files, max is %v",
			countTextFiles, www.PolicyMaxMDs)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusTextFileCountInvalid,
			ErrorContext: []string{e},
		}
	}
	if countImageFiles > www.PolicyMaxImages {
		e := fmt.Sprintf("got %v image files, max is %v",
			countImageFiles, www.PolicyMaxImages)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusImageFileCountInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify that the metadata contains a ProposalMetadata and only
	// a ProposalMetadata.
	switch {
	case len(metadata) == 0:
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropMetadataNotFound,
		}
	case len(metadata) > 1:
		e := fmt.Sprintf("metadata should only contain %v",
			www.HintProposalMetadata)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusMetadataCountInvalid,
			ErrorContext: []string{e},
		}
	}
	md := metadata[0]
	if md.Hint != www.HintProposalMetadata {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropMetadataNotFound,
		}
	}

	// Verify metadata fields
	b, err := base64.StdEncoding.DecodeString(md.Payload)
	if err != nil {
		e := fmt.Sprintf("metadata with hint %v invalid base64 payload", md.Hint)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusMetadataPayloadInvalid,
			ErrorContext: []string{e},
		}
	}
	digest := util.Digest(b)
	if md.Digest != hex.EncodeToString(digest) {
		e := fmt.Sprintf("metadata with hint %v got digest %v, want %v",
			md.Hint, md.Digest, hex.EncodeToString(digest))
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusMetadataDigestInvalid,
			ErrorContext: []string{e},
		}
	}

	// Decode ProposalMetadata
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var pm pi.ProposalMetadata
	err = d.Decode(&pm)
	if err != nil {
		e := fmt.Sprintf("unable to decode %v payload", md.Hint)
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusMetadataPayloadInvalid,
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

func (p *politeiawww) processProposalNew(pn pi.ProposalNew, usr user.User) (*pi.ProposalNewReply, error) {
	log.Tracef("processProposalNew: %v", usr.Username)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user has a proposal credit
	if !p.userHasProposalCredits(usr) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserBalanceInsufficient,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != pn.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
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
	// politeiad files instead of metadata streams since they contain
	// user defined data that needs to be included in the merkle root
	// that politeiad signs.
	files := convertFilesFromPi(pn.Files)
	for _, v := range pn.Metadata {
		switch v.Hint {
		case pi.HintProposalMetadata:
			files = append(files, convertFileFromMetadata(v))
		}
	}

	// Setup metadata stream
	timestamp := time.Now().Unix()
	pg := piplugin.ProposalGeneral{
		UserID:    usr.ID.String(),
		PublicKey: pn.PublicKey,
		Signature: pn.Signature,
		Timestamp: timestamp,
	}
	b, err := piplugin.EncodeProposalGeneral(pg)
	if err != nil {
		return nil, err
	}
	metadata := []pd.MetadataStream{
		{
			ID:      piplugin.MDStreamIDProposalGeneral,
			Payload: string(b),
		},
	}

	// Send politeiad request
	dcr, err := p.newRecord(metadata, files)
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

	return &pi.ProposalNewReply{
		Timestamp:        timestamp,
		CensorshipRecord: cr,
	}, nil
}

// filesToDel returns the names of the files that are included in current but
// are not included in updated. These are the files that need to be deleted
// from a proposal on update.
func filesToDel(current []pi.File, updated []pi.File) []string {
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

func (p *politeiawww) processProposalEdit(pe pi.ProposalEdit, usr user.User) (*pi.ProposalEditReply, error) {
	log.Tracef("processProposalEdit: %v", pe.Token)

	// Verify token
	if !tokenIsFullLength(pe.Token) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropTokenInvalid,
		}
	}

	// Verify state
	switch pe.State {
	case pi.PropStateUnvetted, pi.PropStateVetted:
		// Allowed; continue
	default:
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropStateInvalid,
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
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Get the current proposal
	curr, err := p.proposalRecordLatest(pe.State, pe.Token)
	if err != nil {
		if err == errProposalNotFound {
			return nil, pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusPropNotFound,
			}
		}
		return nil, err
	}

	// Verify the user is the author. The public keys are not static
	// values so the user IDs must be compared directly.
	if curr.UserID != usr.ID.String() {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserIsNotAuthor,
		}
	}

	// Verification that requires retrieving the existing proposal is
	// done in the politeiad pi plugin hook. This includes:
	// -Verify proposal status
	// -Verify vote status
	// -Verify linkto

	// Setup politeiad files. The Metadata objects are converted to
	// politeiad files instead of metadata streams since they contain
	// user defined data that needs to be included in the merkle root
	// that politeiad signs.
	filesAdd := convertFilesFromPi(pe.Files)
	for _, v := range pe.Metadata {
		switch v.Hint {
		case pi.HintProposalMetadata:
			filesAdd = append(filesAdd, convertFileFromMetadata(v))
		}
	}
	filesDel := filesToDel(curr.Files, pe.Files)

	// Setup politeiad metadata
	timestamp := time.Now().Unix()
	pg := piplugin.ProposalGeneral{
		UserID:    usr.ID.String(),
		PublicKey: pe.PublicKey,
		Signature: pe.Signature,
		Timestamp: timestamp,
	}
	b, err := piplugin.EncodeProposalGeneral(pg)
	if err != nil {
		return nil, err
	}
	mdOverwrite := []pd.MetadataStream{
		{
			ID:      piplugin.MDStreamIDProposalGeneral,
			Payload: string(b),
		},
	}
	mdAppend := []pd.MetadataStream{}

	// Send politeiad request
	// TODO verify that this will throw an error if no proposal files
	// were changed.
	var r *pd.Record
	switch pe.State {
	case pi.PropStateUnvetted:
		r, err = p.updateUnvetted(pe.Token, mdAppend, mdOverwrite,
			filesAdd, filesDel)
		if err != nil {
			return nil, err
		}
	case pi.PropStateVetted:
		r, err = p.updateVetted(pe.Token, mdAppend, mdOverwrite,
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

	return &pi.ProposalEditReply{
		CensorshipRecord: convertCensorshipRecordFromPD(r.CensorshipRecord),
		Timestamp:        timestamp,
	}, nil
}

func (p *politeiawww) processProposalSetStatus(pss pi.ProposalSetStatus, usr user.User) (*pi.ProposalSetStatusReply, error) {
	log.Tracef("processProposalSetStatus: %v %v", pss.Token, pss.Status)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify token
	if !tokenIsFullLength(pss.Token) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropTokenInvalid,
		}
	}

	// Verify state
	switch pss.State {
	case pi.PropStateUnvetted, pi.PropStateVetted:
		// Allowed; continue
	default:
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusPropStateInvalid,
		}
	}

	// Verify reason
	_, required := statusReasonRequired[pss.Status]
	if required && pss.Reason == "" {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPropStatusChangeReasonInvalid,
			ErrorContext: []string{"reason not given"},
		}
	}

	// Verify user is an admin
	if !usr.Admin {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserIsNotAdmin,
		}
	}

	// Verify user signed with their active identity
	if usr.PublicKey() != pss.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Verify signature
	msg := pss.Token + pss.Version + strconv.Itoa(int(pss.Status)) + pss.Reason
	err := util.VerifySignature(pss.Signature, pss.PublicKey, msg)
	if err != nil {
		return nil, convertUserErrorFromSignatureError(err)
	}

	// Verification that requires retrieving the existing proposal is
	// done in politeiad. This includes:
	// -Verify proposal exists (politeiad)
	// -Verify proposal state is correct (politeiad)
	// -Verify version is the latest version (politeiad pi plugin)
	// -Verify status change is allowed (politeiad pi plugin)

	// Setup metadata
	timestamp := time.Now().Unix()
	sc := piplugin.StatusChange{
		Token:     pss.Token,
		Version:   pss.Version,
		Status:    piplugin.PropStatusT(pss.Status),
		Reason:    pss.Reason,
		PublicKey: pss.PublicKey,
		Signature: pss.Signature,
		Timestamp: timestamp,
	}
	b, err := piplugin.EncodeStatusChange(sc)
	if err != nil {
		return nil, err
	}
	mdAppend := []pd.MetadataStream{
		{
			ID:      piplugin.MDStreamIDStatusChanges,
			Payload: string(b),
		},
	}
	mdOverwrite := []pd.MetadataStream{}

	// Send politeiad request
	// TODO verify proposal not found error is returned when wrong
	// token or state is used
	var r *pd.Record
	status := convertRecordStatusFromPropStatus(pss.Status)
	switch pss.State {
	case pi.PropStateUnvetted:
		r, err = p.setUnvettedStatus(pss.Token, status, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	case pi.PropStateVetted:
		r, err = p.setVettedStatus(pss.Token, status, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}
	}

	// Emit status change event
	p.eventManager.emit(eventProposalStatusChange,
		dataProposalStatusChange{
			token:   pss.Token,
			status:  convertPropStatusFromPD(r.Status),
			version: r.Version,
			reason:  pss.Reason,
			adminID: usr.ID.String(),
		})

	return &pi.ProposalSetStatusReply{
		Timestamp: timestamp,
	}, nil
}

func (p *politeiawww) processProposals(ps pi.Proposals, isAdmin bool) (*pi.ProposalsReply, error) {
	log.Tracef("processProposals: %v", ps.Requests)

	props, err := p.proposalRecords(ps.State, ps.Requests, ps.IncludeFiles)
	if err != nil {
		return nil, err
	}

	// Only admins are allowed to retrieve unvetted proposal files.
	// Remove all unvetted proposal files and user defined metadata if
	// the user is not an admin.
	if !isAdmin {
		for k, v := range props {
			if v.State == pi.PropStateVetted {
				continue
			}
			v.Files = []pi.File{}
			v.Metadata = []pi.Metadata{}
			props[k] = v
		}
	}

	return &pi.ProposalsReply{
		Proposals: props,
	}, nil
}

func (p *politeiawww) processProposalInventory(isAdmin bool) (*pi.ProposalInventoryReply, error) {
	log.Tracef("processProposalInventory")

	ir, err := p.inventoryByStatus()
	if err != nil {
		return nil, err
	}
	reply := pi.ProposalInventoryReply{
		Unvetted:  append(ir.Unvetted, ir.IterationUnvetted...),
		Public:    ir.Vetted,
		Censored:  ir.Censored,
		Abandoned: ir.Archived,
	}

	// Remove unvetted data from non-admin users
	if !isAdmin {
		reply.Unvetted = []string{}
		reply.Censored = []string{}
	}

	return &reply, nil
}

func (p *politeiawww) processCommentNew(cn pi.CommentNew, usr user.User) (*pi.CommentNewReply, error) {
	log.Tracef("processCommentNew: %v", usr.Username)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != cn.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	pcn := piplugin.CommentNew{
		UserID:    usr.ID.String(),
		State:     convertPropStateFromPi(cn.State),
		Token:     cn.Token,
		ParentID:  cn.ParentID,
		Comment:   cn.Comment,
		PublicKey: cn.PublicKey,
		Signature: cn.Signature,
	}
	cnr, err := p.piCommentNew(pcn)
	if err != nil {
		return nil, err
	}

	// Emit event
	p.eventManager.emit(eventProposalComment,
		dataProposalComment{
			state:     cn.State,
			token:     cn.Token,
			commentID: cnr.CommentID,
			parentID:  cn.ParentID,
			username:  usr.Username,
		})

	return &pi.CommentNewReply{
		CommentID: cnr.CommentID,
		Timestamp: cnr.Timestamp,
		Receipt:   cnr.Receipt,
	}, nil
}

func (p *politeiawww) processCommentVote(cv pi.CommentVote, usr user.User) (*pi.CommentVoteReply, error) {
	log.Tracef("processCommentVote: %v %v %v", cv.Token, cv.CommentID, cv.Vote)

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, pi.UserErrorReply{
			ErrorCode: pi.ErrorStatusUserRegistrationNotPaid,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != cv.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	pcv := piplugin.CommentVote{
		UserID:    usr.ID.String(),
		State:     convertPropStateFromPi(cv.State),
		Token:     cv.Token,
		CommentID: cv.CommentID,
		Vote:      convertCommentVoteFromPi(cv.Vote),
		PublicKey: cv.PublicKey,
		Signature: cv.Signature,
	}
	cvr, err := p.piCommentVote(pcv)
	if err != nil {
		return nil, err
	}

	return &pi.CommentVoteReply{
		Score:     cvr.Score,
		Timestamp: cvr.Timestamp,
		Receipt:   cvr.Receipt,
	}, nil
}

func (p *politeiawww) processCommentCensor(cc pi.CommentCensor, usr user.User) (*pi.CommentCensorReply, error) {
	log.Tracef("processCommentCensor: %v %v", cc.Token, cc.CommentID)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify user signed with their active identity
	if usr.PublicKey() != cc.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	pcc := piplugin.CommentCensor{
		State:     convertPropStateFromPi(cc.State),
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,
	}
	ccr, err := p.piCommentCensor(pcc)
	if err != nil {
		return nil, err
	}

	return &pi.CommentCensorReply{
		Timestamp: ccr.Timestamp,
		Receipt:   ccr.Receipt,
	}, nil
}

func (p *politeiawww) processComments(c pi.Comments) (*pi.CommentsReply, error) {
	log.Tracef("processComments: %v", c.Token)

	// Send plugin command
	reply, err := p.commentsAll(comments.GetAll{
		State: convertCommentsStateFromPi(c.State),
		Token: c.Token,
	})
	if err != nil {
		return nil, err
	}

	// Prepare reply. Comments contain user data that needs to be
	// pulled from the user database.
	cs := make([]pi.Comment, 0, len(reply.Comments))
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

	return &pi.CommentsReply{
		Comments: cs,
	}, nil
}

func (p *politeiawww) processCommentVotes(cv pi.CommentVotes) (*pi.CommentVotesReply, error) {
	log.Tracef("processCommentVotes: %v %v", cv.Token, cv.UserID)

	v := comments.Votes{
		State:  convertCommentsStateFromPi(cv.State),
		Token:  cv.Token,
		UserID: cv.UserID,
	}
	cvr, err := p.commentVotes(v)
	if err != nil {
		return nil, err
	}

	return &pi.CommentVotesReply{
		Votes: convertCommentVoteDetailsFromPlugin(cvr.Votes),
	}, nil
}

func (p *politeiawww) processVoteAuthorize(va pi.VoteAuthorize, usr user.User) (*pi.VoteAuthorizeReply, error) {
	log.Tracef("processVoteAuthorize: %v", va.Token)

	// Verify user signed with their active identity
	if usr.PublicKey() != va.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Send plugin command
	ar, err := p.voteAuthorize(convertVoteAuthorizeFromPi(va))
	if err != nil {
		return nil, err
	}

	return &pi.VoteAuthorizeReply{
		Timestamp: ar.Timestamp,
		Receipt:   ar.Receipt,
	}, nil
}

func (p *politeiawww) processVoteStart(vs pi.VoteStart, usr user.User) (*pi.VoteStartReply, error) {
	log.Tracef("processVoteStart: %v", vs.Params.Token)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify admin signed with their active identity
	if usr.PublicKey() != vs.PublicKey {
		return nil, pi.UserErrorReply{
			ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"not active identity"},
		}
	}

	// Call the ticketvote plugin to start vote
	reply, err := p.voteStart(convertVoteStartFromPi(vs))
	if err != nil {
		return nil, err
	}

	return &pi.VoteStartReply{
		StartBlockHeight: reply.StartBlockHeight,
		StartBlockHash:   reply.StartBlockHash,
		EndBlockHeight:   reply.EndBlockHeight,
		EligibleTickets:  reply.EligibleTickets,
	}, nil
}

func (p *politeiawww) processVoteStartRunoff(vsr pi.VoteStartRunoff, usr user.User) (*pi.VoteStartRunoffReply, error) {
	log.Tracef("processVoteStartRunoff: %v", vsr.Token)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify admin signed all authorizations and starts using their
	// active identity.
	for _, v := range vsr.Auths {
		if usr.PublicKey() != v.PublicKey {
			e := fmt.Sprintf("authorize %v public key is not the active identity",
				v.Token)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
				ErrorContext: []string{e},
			}
		}
	}
	for _, v := range vsr.Starts {
		if usr.PublicKey() != v.PublicKey {
			e := fmt.Sprintf("start %v public key is not the active identity",
				v.Params.Token)
			return nil, pi.UserErrorReply{
				ErrorCode:    pi.ErrorStatusPublicKeyInvalid,
				ErrorContext: []string{e},
			}
		}
	}

	// Send plugin command
	tsr := ticketvote.StartRunoff{
		Token:  vsr.Token,
		Auths:  convertVoteAuthsFromPi(vsr.Auths),
		Starts: convertVoteStartsFromPi(vsr.Starts),
	}
	srr, err := p.voteStartRunoff(tsr)
	if err != nil {
		return nil, err
	}

	return &pi.VoteStartRunoffReply{
		StartBlockHeight: srr.StartBlockHeight,
		StartBlockHash:   srr.StartBlockHash,
		EndBlockHeight:   srr.EndBlockHeight,
		EligibleTickets:  srr.EligibleTickets,
	}, nil
}

func (p *politeiawww) processVoteBallot(vb pi.VoteBallot) (*pi.VoteBallotReply, error) {
	log.Tracef("processVoteBallot")

	b := ticketvote.Ballot{
		Votes: convertCastVotesFromPi(vb.Votes),
	}
	reply, err := p.voteBallot(b)
	if err != nil {
		return nil, err
	}

	return &pi.VoteBallotReply{
		Receipts: convertCastVoteRepliesFromPlugin(reply.Receipts),
	}, nil
}

func (p *politeiawww) processVotes(v pi.Votes) (*pi.VotesReply, error) {
	log.Tracef("processVotes: %v", v.Tokens)

	vd, err := p.voteDetails(v.Tokens)
	if err != nil {
		return nil, err
	}

	return &pi.VotesReply{
		Votes: convertProposalVotesFromPlugin(vd.Votes),
	}, nil
}

func (p *politeiawww) processVoteResults(vr pi.VoteResults) (*pi.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", vr.Token)

	cvr, err := p.castVotes(vr.Token)
	if err != nil {
		return nil, err
	}

	return &pi.VoteResultsReply{
		Votes: convertCastVoteDetailsFromPlugin(cvr.Votes),
	}, nil
}

func (p *politeiawww) processVoteSummaries(vs pi.VoteSummaries) (*pi.VoteSummariesReply, error) {
	log.Tracef("processVoteSummaries: %v", vs.Tokens)

	r, err := p.voteSummaries(vs.Tokens)
	if err != nil {
		return nil, err
	}

	return &pi.VoteSummariesReply{
		Summaries: convertVoteSummariesFromPlugin(r.Summaries),
		BestBlock: r.BestBlock,
	}, nil
}

func (p *politeiawww) processVoteInventory() (*pi.VoteInventoryReply, error) {
	log.Tracef("processVoteInventory")

	r, err := p.piVoteInventory()
	if err != nil {
		return nil, err
	}

	return &pi.VoteInventoryReply{
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

	var pn pi.ProposalNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pn); err != nil {
		respondWithPiError(w, r, "handleProposalNew: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalNew: getSessionUser: %v", err)
		return
	}

	pnr, err := p.processProposalNew(pn, *user)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalNew: processProposalNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pnr)
}

func (p *politeiawww) handleProposalEdit(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalEdit")

	var pe pi.ProposalEdit
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pe); err != nil {
		respondWithPiError(w, r, "handleProposalEdit: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalEdit: getSessionUser: %v", err)
		return
	}

	per, err := p.processProposalEdit(pe, *user)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalEdit: processProposalEdit: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, per)
}

func (p *politeiawww) handleProposalSetStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalSetStatus")

	var pss pi.ProposalSetStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pss); err != nil {
		respondWithPiError(w, r, "handleProposalSetStatus: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalSetStatus: getSessionUser: %v", err)
		return
	}

	pssr, err := p.processProposalSetStatus(pss, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalSetStatus: processProposalSetStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pssr)
}

func (p *politeiawww) handleProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposals")

	var ps pi.Proposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ps); err != nil {
		respondWithPiError(w, r, "handleProposals: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
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
	ppi, err := p.processProposals(ps, isAdmin)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposals: processProposals: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ppi)
}

func (p *politeiawww) handleProposalInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalInventory")

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposalInventory: getSessionUser: %v", err)
		return
	}

	isAdmin := usr != nil && usr.Admin
	ppi, err := p.processProposalInventory(isAdmin)
	if err != nil {
		respondWithPiError(w, r,
			"handleProposalInventory: processProposalInventory: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ppi)
}

func (p *politeiawww) handleCommentNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentNew")

	var cn pi.CommentNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cn); err != nil {
		respondWithPiError(w, r, "handleCommentNew: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: getSessionUser: %v", err)
		return
	}

	cnr, err := p.processCommentNew(cn, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: processCommentNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cnr)
}

func (p *politeiawww) handleCommentVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVote")

	var cv pi.CommentVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		respondWithPiError(w, r, "handleCommentVote: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: getSessionUser: %v", err)
	}

	vcr, err := p.processCommentVote(cv, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processCommentVote: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vcr)
}

func (p *politeiawww) handleCommentCensor(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentCensor")

	var cc pi.CommentCensor
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cc); err != nil {
		respondWithPiError(w, r, "handleCommentCensor: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentCensor: getSessionUser: %v", err)
		return
	}

	ccr, err := p.processCommentCensor(cc, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentCensor: processCommentCensor: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, ccr)
}

func (p *politeiawww) handleComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleComments")

	var c pi.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithPiError(w, r, "handleComments: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	cr, err := p.processComments(c)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processComments: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

func (p *politeiawww) handleCommentVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVotes")

	var cv pi.CommentVotes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		respondWithPiError(w, r, "handleCommentVotes: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	cvr, err := p.processCommentVotes(cv)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVotes: processCommentVotes: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, cvr)
}

func (p *politeiawww) handleVoteAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteAuthorize")

	var va pi.VoteAuthorize
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&va); err != nil {
		respondWithPiError(w, r, "handleVoteAuthorize: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteAuthorize: getSessionUser: %v", err)
	}

	vr, err := p.processVoteAuthorize(va, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteAuthorize: processVoteAuthorize: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleVoteStart(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteStart")

	var vs pi.VoteStart
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "handleVoteStart: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStart: getSessionUser: %v", err)
	}

	vsr, err := p.processVoteStart(vs, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStart: processVoteStart: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleVoteStartRunoff(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteStartRunoff")

	var vsr pi.VoteStartRunoff
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vsr); err != nil {
		respondWithPiError(w, r, "handleVoteStartRunoff: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStartRunoff: getSessionUser: %v", err)
	}

	vsrr, err := p.processVoteStartRunoff(vsr, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteStartRunoff: processVoteStartRunoff: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vsrr)
}

func (p *politeiawww) handleVoteBallot(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteBallot")

	var vb pi.VoteBallot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vb); err != nil {
		respondWithPiError(w, r, "handleVoteBallot: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	vbr, err := p.processVoteBallot(vb)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteBallot: processVoteBallot: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vbr)
}

func (p *politeiawww) handleVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVotes")

	var v pi.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithPiError(w, r, "handleVotes: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	vr, err := p.processVotes(v)
	if err != nil {
		respondWithPiError(w, r,
			"handleVotes: processVotes: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	var vr pi.VoteResults
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vr); err != nil {
		respondWithPiError(w, r, "handleVoteResults: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	vrr, err := p.processVoteResults(vr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteResults: prcoessVoteResults: %v", err)
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

func (p *politeiawww) handleVoteSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteSummaries")

	var vs pi.VoteSummaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	vsr, err := p.processVoteSummaries(vs)
	if err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: processVoteSummaries: %v",
			err)
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleVoteInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteInventory")

	var vi pi.VoteInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vi); err != nil {
		respondWithPiError(w, r, "handleVoteInventory: unmarshal",
			pi.UserErrorReply{
				ErrorCode: pi.ErrorStatusInputInvalid,
			})
		return
	}

	vir, err := p.processVoteInventory()
	if err != nil {
		respondWithPiError(w, r, "handleVoteInventory: processVoteInventory: %v",
			err)
	}

	util.RespondWithJSON(w, http.StatusOK, vir)
}

// setPiRoutes sets the pi API routes.
func (p *politeiawww) setPiRoutes() {
	// Proposal routes
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteProposalNew, p.handleProposalNew,
		permissionLogin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteProposalEdit, p.handleProposalEdit,
		permissionLogin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteProposalSetStatus, p.handleProposalSetStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteProposals, p.handleProposals,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteProposalInventory, p.handleProposalInventory,
		permissionPublic)

	// Comment routes
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteCommentNew, p.handleCommentNew,
		permissionLogin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteCommentVote, p.handleCommentVote,
		permissionLogin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteCommentCensor, p.handleCommentCensor,
		permissionAdmin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteComments, p.handleComments,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteCommentVotes, p.handleCommentVotes,
		permissionPublic)

	// Vote routes
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteAuthorize, p.handleVoteAuthorize,
		permissionLogin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteStart, p.handleVoteStart,
		permissionAdmin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteStartRunoff, p.handleVoteStartRunoff,
		permissionAdmin)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteBallot, p.handleVoteBallot,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVotes, p.handleVotes,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteResults, p.handleVoteResults,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteSummaries, p.handleVoteSummaries,
		permissionPublic)
	p.addRoute(http.MethodPost, pi.APIRoute,
		pi.RouteVoteInventory, p.handleVoteInventory,
		permissionPublic)
}
