// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
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
func (p *piPlugin) hookCommentNew(token []byte) error {
	return p.commentWritesAllowed(token)
}

// hookCommentDel adds pi specific validation onto the comments plugin Del
// command.
func (p *piPlugin) hookCommentDel(token []byte) error {
	return p.commentWritesAllowed(token)
}

// hookCommentVote adds pi specific validation onto the comments plugin Vote
// command.
func (p *piPlugin) hookCommentVote(token []byte) error {
	return p.commentWritesAllowed(token)
}

// hookPluginPre extends plugin write commands from other plugins with pi
// specific validation.
func (p *piPlugin) hookPluginPre(treeID int64, token []byte, payload string) error {
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
			return p.hookCommentNew(token)
		case comments.CmdDel:
			return p.hookCommentDel(token)
		case comments.CmdVote:
			return p.hookCommentVote(token)
		}
	}

	return nil
}

// proposalNameIsValid returns whether the provided name is a valid proposal
// name.
func (p *piPlugin) proposalNameIsValid(name string) bool {
	return p.proposalNameRegexp.MatchString(name)
}

// proposalFilesVerify verifies the files adhere to all pi plugin setting
// requirements. If this hook is being executed then the files have already
// passed politeiad validation so we can assume that the file has a unique
// name, a valid base64 payload, and that the file digest and MIME type are
// correct.
func (p *piPlugin) proposalFilesVerify(files []backend.File) error {
	var imagesCount uint32
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return fmt.Errorf("invalid base64 %v", v.Name)
		}

		// MIME type specific validation
		switch v.MIME {
		case mimeTypeText, mimeTypeTextUTF8:
			// Verify text file is allowed
			_, ok := allowedTextFiles[v.Name]
			if !ok {
				return backend.PluginError{
					PluginID:     pi.PluginID,
					ErrorCode:    uint32(pi.ErrorCodeTextFileNameInvalid),
					ErrorContext: v.Name,
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
			return fmt.Errorf("invalid mime: %v", v.MIME)
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

	// Verify proposal name
	if !p.proposalNameIsValid(pm.Name) {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeProposalNameInvalid),
			ErrorContext: p.proposalNameRegexp.String(),
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

// commentWritesAllowed verifies that a proposal has a vote status that allows
// comment writes to be made to the proposal. This includes both comments and
// comment votes. Comment writes are allowed up until the proposal has finished
// voting.
func (p *piPlugin) commentWritesAllowed(token []byte) error {
	vs, err := p.voteSummary(token)
	if err != nil {
		return err
	}
	switch vs.Status {
	case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
		ticketvote.VoteStatusStarted:
		// Comment writes are allowed on these vote statuses
		return nil
	default:
		// Vote status does not allow writes
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeVoteStatusInvalid),
			ErrorContext: "vote has ended; proposal is locked",
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
