// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// Accepted MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
)

var (
	// allowedTextFiles contains the filenames of the only text files
	// that are allowed to be submitted as part of a proposal.
	allowedTextFiles = map[string]struct{}{
		pi.FileNameIndexFile:            {},
		pi.FileNameProposalMetadata:     {},
		ticketvote.FileNameVoteMetadata: {},
	}
)

// hookNewRecordPre adds plugin specific validation onto the tstore backend
// RecordNew method.
func (p *piPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	return p.proposalFilesVerify(nr.Files)
}

// hookEditRecordPre adds plugin specific validation onto the tstore backend
// RecordEdit method.
func (p *piPlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify proposal files
	err = p.proposalFilesVerify(er.Files)
	if err != nil {
		return err
	}

	// Verify vote status. Edits are not allowed to be made once a vote
	// has been authorized. This only needs to be checked for vetted
	// records since you cannot authorize or start a ticket vote on an
	// unvetted record.
	if er.RecordMetadata.State == backend.StateVetted {
		t, err := tokenDecode(er.RecordMetadata.Token)
		if err != nil {
			return err
		}
		s, err := p.voteSummary(t)
		if err != nil {
			return err
		}
		if s.Status != ticketvote.VoteStatusUnauthorized {
			return backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeVoteStatusInvalid),
				ErrorContext: fmt.Sprintf("vote status '%v' "+
					"does not allow for proposal edits",
					ticketvote.VoteStatuses[s.Status]),
			}
		}
	}

	return nil
}

// hookCommentNew adds pi specific validation onto the comments plugin New
// command.
func (p *piPlugin) hookCommentNew(token []byte, cmd, payload string) error {
	return p.commentWritesAllowed(token, cmd, payload)
}

// hookCommentDel adds pi specific validation onto the comments plugin Del
// command.
func (p *piPlugin) hookCommentDel(token []byte, cmd, payload string) error {
	return p.commentWritesAllowed(token, cmd, payload)
}

// hookCommentVote adds pi specific validation onto the comments plugin Vote
// command.
func (p *piPlugin) hookCommentVote(token []byte, cmd, payload string) error {
	return p.commentWritesAllowed(token, cmd, payload)
}

// hookPluginPre extends plugin write commands from other plugins with pi
// specific validation.
func (p *piPlugin) hookPluginPre(payload string) error {
	// Decode payload
	var hpp plugins.HookPluginPre
	err := json.Unmarshal([]byte(payload), &hpp)
	if err != nil {
		return err
	}

	// Call plugin hook
	switch hpp.PluginID {
	case comments.PluginID:
		switch hpp.Cmd {
		case comments.CmdNew:
			return p.hookCommentNew(hpp.Token, hpp.Cmd, hpp.Payload)
		case comments.CmdDel:
			return p.hookCommentDel(hpp.Token, hpp.Cmd, hpp.Payload)
		case comments.CmdVote:
			return p.hookCommentVote(hpp.Token, hpp.Cmd, hpp.Payload)
		}
	}

	return nil
}

// titleIsValid returns whether the provided title, which can be either a
// proposal name or an author update title, matches the pi plugin title regex.
func (p *piPlugin) titleIsValid(title string) bool {
	return p.titleRegexp.MatchString(title)
}

// proposalStartDateIsValid returns whether the provided start date is valid.
//
// A valid start date of a proposal must be after the minimum start date
// set by the proposalStartDateMin plugin setting.
func (p *piPlugin) proposalStartDateIsValid(start int64) bool {
	return start > time.Now().Unix()+p.proposalStartDateMin
}

// proposalEndDateIsValid returns whether the provided end date is valid.
//
// A valid end date must be after the start date and before the end of the
// time interval set by the proposalEndDateMax plugin setting.
func (p *piPlugin) proposalEndDateIsValid(start int64, end int64) bool {
	return end > start &&
		time.Now().Unix()+p.proposalEndDateMax > end
}

// proposalAmountIsValid returns whether the provided amount is in the range
// defined by the proposalAmountMin & proposalAmountMax plugin settings.
func (p *piPlugin) proposalAmountIsValid(amount uint64) bool {
	return p.proposalAmountMin <= amount &&
		p.proposalAmountMax >= amount
}

// proposalDomainIsValid returns whether the provided domain is
// is a valid proposal domain.
func (p *piPlugin) proposalDomainIsValid(domain string) bool {
	_, found := p.proposalDomains[domain]
	return found
}

// isRFP returns true if the given vote metadata contains the metadata for
// an RFP.
func isRFP(vm *ticketvote.VoteMetadata) bool {
	return vm != nil && vm.LinkBy != 0
}

// proposalFilesVerify verifies the files adhere to all pi plugin setting
// requirements. If this hook is being executed then the files have already
// passed politeiad validation so we can assume that the file has a unique
// name, a valid base64 payload, and that the file digest and MIME type are
// correct.
func (p *piPlugin) proposalFilesVerify(files []backend.File) error {
	// Sanity check
	if len(files) == 0 {
		return errors.Errorf("no files found")
	}

	// Verify file types and sizes
	var imagesCount uint32
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return errors.Errorf("invalid base64 %v", v.Name)
		}

		// MIME type specific validation
		switch v.MIME {
		case mimeTypeText, mimeTypeTextUTF8:
			// Verify text file is allowed
			_, ok := allowedTextFiles[v.Name]
			if !ok {
				allowed := make([]string, 0, len(allowedTextFiles))
				for name := range allowedTextFiles {
					allowed = append(allowed, name)
				}
				return backend.PluginError{
					PluginID:  pi.PluginID,
					ErrorCode: uint32(pi.ErrorCodeTextFileNameInvalid),
					ErrorContext: fmt.Sprintf("invalid text file name "+
						"%v; allowed text file names are %v",
						v.Name, strings.Join(allowed, ", ")),
				}
			}

			// Verify text file size
			if len(payload) > int(p.textFileSizeMax) {
				return backend.PluginError{
					PluginID:  pi.PluginID,
					ErrorCode: uint32(pi.ErrorCodeTextFileSizeInvalid),
					ErrorContext: fmt.Sprintf("file %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						p.textFileSizeMax),
				}
			}

		case mimeTypePNG:
			imagesCount++

			// Verify image file size
			if len(payload) > int(p.imageFileSizeMax) {
				return backend.PluginError{
					PluginID:  pi.PluginID,
					ErrorCode: uint32(pi.ErrorCodeImageFileSizeInvalid),
					ErrorContext: fmt.Sprintf("image %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						p.imageFileSizeMax),
				}
			}

		default:
			return errors.Errorf("invalid mime: %v", v.MIME)
		}
	}

	// Verify that an index file is present
	var found bool
	for _, v := range files {
		if v.Name == pi.FileNameIndexFile {
			found = true
			break
		}
	}
	if !found {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeTextFileMissing),
			ErrorContext: pi.FileNameIndexFile,
		}
	}

	// Verify image file count is acceptable
	if imagesCount > p.imageFileCountMax {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeImageFileCountInvalid),
			ErrorContext: fmt.Sprintf("got %v image files, max "+
				"is %v", imagesCount, p.imageFileCountMax),
		}
	}

	// Verify a proposal metadata has been included
	pm, err := proposalMetadataDecode(files)
	if err != nil {
		return err
	}
	if pm == nil {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeTextFileMissing),
			ErrorContext: pi.FileNameProposalMetadata,
		}
	}

	// Validate vote & proposal metadata requirements
	vm, err := voteMetadataDecode(files)
	if err != nil {
		return err
	}
	// In case of an RFP ensure irrelevant proposal metadata are not provided.
	if isRFP(vm) {
		switch {
		case pm.Amount != 0:
			return backend.PluginError{
				PluginID:     pi.PluginID,
				ErrorCode:    uint32(pi.ErrorCodeProposalAmountInvalid),
				ErrorContext: "RFP metadata should not include an amount",
			}
		case pm.StartDate != 0:
			return backend.PluginError{
				PluginID:     pi.PluginID,
				ErrorCode:    uint32(pi.ErrorCodeProposalStartDateInvalid),
				ErrorContext: "RFP metadata should not include a start date",
			}
		case pm.EndDate != 0:
			return backend.PluginError{
				PluginID:     pi.PluginID,
				ErrorCode:    uint32(pi.ErrorCodeProposalEndDateInvalid),
				ErrorContext: "RFP metadata should not include an end date",
			}
		}
	}

	// Verify proposal name
	if !p.titleIsValid(pm.Name) {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeTitleInvalid),
			ErrorContext: p.titleRegexp.String(),
		}
	}

	// Validate proposal domain.
	if !p.proposalDomainIsValid(pm.Domain) {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeProposalDomainInvalid),
			ErrorContext: fmt.Sprintf("got %v domain, "+
				"supported domains are: %v", pm.Domain, p.proposalDomains),
		}
	}

	// If not RFP validate rest of proposal metadata fields
	if !isRFP(vm) {
		// Validate proposal start date.
		if !p.proposalStartDateIsValid(pm.StartDate) {
			return backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeProposalStartDateInvalid),
				ErrorContext: fmt.Sprintf("got %v start date, min is %v",
					pm.StartDate, time.Now().Unix()),
			}
		}

		// Validate proposal end date.
		if !p.proposalEndDateIsValid(pm.StartDate, pm.EndDate) {
			return backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeProposalEndDateInvalid),
				ErrorContext: fmt.Sprintf("got %v end date, min is start date %v, "+
					"max is %v",
					pm.EndDate,
					pm.StartDate,
					time.Now().Unix()+pi.SettingProposalEndDateMax),
			}
		}

		// Validate proposal amount.
		if !p.proposalAmountIsValid(pm.Amount) {
			return backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeProposalAmountInvalid),
				ErrorContext: fmt.Sprintf("got %v amount, min is %v, "+
					"max is %v", pm.Amount, p.proposalAmountMin, p.proposalAmountMax),
			}
		}
	}

	return nil
}

// voteSummary requests the vote summary from the ticketvote plugin for a
// record.
func (p *piPlugin) voteSummary(token []byte) (*ticketvote.SummaryReply, error) {
	reply, err := p.backend.PluginRead(token, ticketvote.PluginID,
		ticketvote.CmdSummary, "")
	if err != nil {
		return nil, err
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(reply), &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// comments requests all comments on a record from the comments plugin.
func (p *piPlugin) comments(token []byte) (*comments.GetAllReply, error) {
	reply, err := p.backend.PluginRead(token, comments.PluginID,
		comments.CmdGetAll, "")
	if err != nil {
		return nil, err
	}
	var gar comments.GetAllReply
	err = json.Unmarshal([]byte(reply), &gar)
	if err != nil {
		return nil, err
	}
	return &gar, nil
}

// isInCommentTree returns whether the leafID is part of the provided comment
// tree. A leaf is considered to be part of the tree if the leaf is a child of
// the root or the leaf references the root itself.
func isInCommentTree(rootID, leafID uint32, cs []comments.Comment) bool {
	if leafID == rootID {
		return true
	}
	// Convert comments slice to a map
	commentsMap := make(map[uint32]comments.Comment, len(cs))
	for _, c := range cs {
		commentsMap[c.CommentID] = c
	}

	// Start with the provided comment leaf and traverse the comment tree up
	// until either the provided root ID is found or we reach the tree head. The
	// tree head will have a comment ID of 0.
	current := commentsMap[leafID]
	for current.ParentID != 0 {
		// Check if next parent in the tree is the rootID.
		if current.ParentID == rootID {
			return true
		}
		leafID = current.ParentID
		current = commentsMap[leafID]
	}
	return false
}

// latestAuthorUpdate gets the latest author update on a record, if
// the record has no author update it returns nil.
func latestAuthorUpdate(token []byte, cs []comments.Comment) *comments.Comment {
	var latestAuthorUpdate comments.Comment
	for _, c := range cs {
		if c.ExtraDataHint != pi.ProposalUpdateHint {
			continue
		}
		if c.Timestamp > latestAuthorUpdate.Timestamp {
			latestAuthorUpdate = c
		}
	}
	return &latestAuthorUpdate
}

// recordAuthor returns the author's userID of the record associated with
// the provided token.
func (p *piPlugin) recordAuthor(token []byte) (string, error) {
	reply, err := p.backend.PluginRead(token, usermd.PluginID,
		usermd.CmdAuthor, "")
	if err != nil {
		return "", err
	}
	var ar usermd.AuthorReply
	err = json.Unmarshal([]byte(reply), &ar)
	if err != nil {
		return "", err
	}
	return ar.UserID, nil
}

// commentVoteAllowedOnApprovedProposal verifies that the given comment
// vote is allowed on a proposal which finished voting and it's vote was
// approved.
func (p *piPlugin) commentVoteAllowedOnApprovedProposal(token []byte, payload string, latestAuthorUpdate comments.Comment, cs []comments.Comment) error {
	// Decode payload
	var v comments.Vote
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return err
	}

	if !isInCommentTree(latestAuthorUpdate.CommentID, v.CommentID, cs) {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeCommentWriteNotAllowed),
			ErrorContext: "votes are only allowed on the author's " +
				"most recent update thread",
		}
	}

	return nil
}

// isValidAuthorUpdate returns whether the given new comment is a valid author
// update.
//
// The comment must include proper proposal update metadata and the comment
// must be submitted by the proposal author for it to be considered a valid
// author update.
func (p *piPlugin) isValidAuthorUpdate(token []byte, n comments.New) error {
	// Get the proposal author. The proposal author
	// and the comment author must be the same user.
	recordAuthorID, err := p.recordAuthor(token)
	if err != nil {
		return err
	}
	if recordAuthorID != n.UserID {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeCommentWriteNotAllowed),
			ErrorContext: "user is not the proposal author",
		}
	}

	// Verify extra data fields
	if n.ExtraDataHint != pi.ProposalUpdateHint {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeExtraDataHintInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v",
				n.ExtraDataHint, pi.ProposalUpdateHint),
		}
	}
	var pum pi.ProposalUpdateMetadata
	err = json.Unmarshal([]byte(n.ExtraData), &pum)
	if err != nil {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeExtraDataInvalid),
		}
	}

	// Verify update title
	if !p.titleIsValid(pum.Title) {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeTitleInvalid),
			ErrorContext: p.titleRegexp.String(),
		}
	}

	// The comment is a valid author update.
	return nil
}

// commentNewAllowedOnApprovedProposal verifies that the given new comment
// is allowed on a proposal which finished voting and it's vote was approved.
func (p *piPlugin) commentNewAllowedOnApprovedProposal(token []byte, payload string, latestAuthorUpdate comments.Comment, cs []comments.Comment) error {
	// Decode payload
	var n comments.New
	err := json.Unmarshal([]byte(payload), &n)
	if err != nil {
		return err
	}

	// A new comment on an approved proposal must either be an update
	// from the author (parent ID will be 0) or a reply to the latest
	// author update.
	isUpdateReply := isInCommentTree(latestAuthorUpdate.CommentID,
		n.ParentID, cs)
	switch {
	case n.ParentID == 0:
		// This might be an update from the author.
		return p.isValidAuthorUpdate(token, n)

	case isUpdateReply:
		// This is a reply to the latest update. This is allowed.
		return nil

	case !isUpdateReply:
		// New comment is a reply, but is not a reply to the latest update. This
		// is not allowed.
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeCommentWriteNotAllowed),
			ErrorContext: "comment replies are only allowed on " +
				"the author's most recent update thread",
		}

	default:
		// This should not happen
		return errors.Errorf("unknown comment write state")
	}
}

// writesAllowedOnApprovedProposal verifies that the given comment write is
// allowed on a proposal which finished voting and it's vote was approved. This
// includes both comments and comment votes.
func (p *piPlugin) writesAllowedOnApprovedProposal(token []byte, cmd, payload string) error {
	// Get billing status to determine whether to allow author updates
	// or not.
	var bsc pi.BillingStatusChange
	billingStatuses, err := p.billingStatuses(token)
	if err != nil {
		return err
	}
	// We assume here that admins can set a billing status only once
	if len(billingStatuses) > 0 {
		bsc = billingStatuses[0]
		if bsc.Status == pi.BillingStatusClosed ||
			bsc.Status == pi.BillingStatusCompleted {
			// If billing status is set to closed or completed, comment writes
			// are not allowed.
			return backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeBillingStatusInvalid),
				ErrorContext: "billing status is set to closed/completed;" +
					" proposal is locked",
			}
		}
	}

	// Get latest proposal author update
	gar, err := p.comments(token)
	if err != nil {
		return err
	}
	latestAuthorUpdate := latestAuthorUpdate(token, gar.Comments)

	switch cmd {
	// If the user is submitting a new comment then it must be either a new
	// author update or a comment on the latest author update thread.
	case comments.CmdNew:
		return p.commentNewAllowedOnApprovedProposal(token, payload,
			*latestAuthorUpdate, gar.Comments)

	// If the user is voting on a comment then it must be on one of the latest
	// author update thread comments.
	case comments.CmdVote:
		return p.commentVoteAllowedOnApprovedProposal(token, payload,
			*latestAuthorUpdate, gar.Comments)

	}

	return nil
}

// commentWritesAllowed verifies that a proposal has a vote status that allows
// comment writes to be made to the proposal. This includes both comments and
// comment votes.
//
// Once a proposal vote has finished, all existing comment threads are locked.
//
// When a proposal author wants to give an update on their **approved**
// proposal they can start a new comment thread.
//
// The author is the only user that will have the ability to
// start a new comment thread once the voting period has finished.
//
// Each update must have an author provided title.
//
// Anyone can reply to any comments in the thread and can cast
// upvotes/downvotes for any comments in the thread.
//
// The comment thread will remain open until either the author starts a new
// update thread or an admin marks the proposal as closed/completed.
func (p *piPlugin) commentWritesAllowed(token []byte, cmd, payload string) error {
	vs, err := p.voteSummary(token)
	if err != nil {
		return err
	}
	switch vs.Status {
	case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
		ticketvote.VoteStatusStarted:
		// Comment writes are allowed on these vote statuses
		return nil

	case ticketvote.VoteStatusApproved:
		return p.writesAllowedOnApprovedProposal(token, cmd, payload)

	default:
		// Vote status does not allow writes
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeCommentWriteNotAllowed),
			ErrorContext: "vote has ended; comments are locked",
		}
	}
}

// tokenDecode returns the decoded censorship token. An error will be returned
// if the token is not a full length token.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// proposalMetadataDecode decodes and returns the ProposalMetadata from the
// provided backend files. If a ProposalMetadata is not found, nil is returned.
func proposalMetadataDecode(files []backend.File) (*pi.ProposalMetadata, error) {
	var propMD *pi.ProposalMetadata
	for _, v := range files {
		if v.Name != pi.FileNameProposalMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var m pi.ProposalMetadata
		err = json.Unmarshal(b, &m)
		if err != nil {
			return nil, err
		}
		propMD = &m
		break
	}
	return propMD, nil
}

// voteMetadataDecode decodes and returns the VoteMetadata from the
// provided backend files. If a VoteMetadata is not found, nil is returned.
func voteMetadataDecode(files []backend.File) (*ticketvote.VoteMetadata, error) {
	var voteMD *ticketvote.VoteMetadata
	for _, v := range files {
		if v.Name != ticketvote.FileNameVoteMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var m ticketvote.VoteMetadata
		err = json.Unmarshal(b, &m)
		if err != nil {
			return nil, err
		}
		voteMD = &m
		break
	}
	return voteMD, nil
}
