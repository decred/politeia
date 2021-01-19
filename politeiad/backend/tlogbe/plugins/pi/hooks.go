// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// proposalMetadataDecode decodes and returns the ProposalMetadata from the
// provided backend files. If a ProposalMetadata is not found, nil is returned.
func proposalMetadataDecode(files []backend.File) (*pi.ProposalMetadata, error) {
	var propMD *pi.ProposalMetadata
	for _, v := range files {
		if v.Name == pi.FileNameProposalMetadata {
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
	}
	return propMD, nil
}

// generalMetadataDecode decodes and returns the GeneralMetadata from the
// provided backend metadata streams. If a GeneralMetadata is not found, nil is
// returned.
func generalMetadataDecode(metadata []backend.MetadataStream) (*pi.GeneralMetadata, error) {
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

// statusChangesDecode decodes a JSON byte slice into a []StatusChange slice.
func statusChangesDecode(payload []byte) ([]pi.StatusChange, error) {
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

func (p *piPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Verify a proposal metadata has been included
	pm, err := proposalMetadataDecode(nr.Files)
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
	var nr plugins.HookNewRecordPost
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Decode GeneralMetadata
	gm, err := generalMetadataDecode(nr.Metadata)
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
					ErrorCode:    int(pi.ErrorCodeVoteStatusInvalid),
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

		statuses, err = statusChangesDecode([]byte(v.Payload))
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
			ErrorCode:    int(pi.ErrorCodePropVersionInvalid),
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
			ErrorCode:    int(pi.ErrorCodePropStatusChangeInvalid),
			ErrorContext: e,
		}
	}

	return nil
}

// commentWritesVerify verifies that a record's vote status allows writes from
// the comments plugin.
func (p *piPlugin) commentWritesVerify(token []byte) error {
	// Verify that the vote status allows comment writes
	vs, err := p.voteSummary(token)
	if err != nil {
		return err
	}
	switch vs.Status {
	case ticketvote.VoteStatusUnauthorized, ticketvote.VoteStatusAuthorized,
		ticketvote.VoteStatusStarted:
		// Writes are allowed on these vote statuses
		return nil
	default:
		return backend.PluginUserError{
			PluginID:     pi.ID,
			ErrorCode:    int(pi.ErrorCodeVoteStatusInvalid),
			ErrorContext: "vote has ended; proposal is locked",
		}
	}
}

func (p *piPlugin) hookCommentNew(token []byte) error {
	return p.commentWritesVerify(token)
}

func (p *piPlugin) hookCommentDel(token []byte) error {
	return p.commentWritesVerify(token)
}

func (p *piPlugin) hookCommentVote(token []byte) error {
	return p.commentWritesVerify(token)
}

func (p *piPlugin) hookPluginPre(treeID int64, token []byte, payload string) error {
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
			return p.hookCommentNew(token)
		case comments.CmdDel:
			return p.hookCommentDel(token)
		case comments.CmdVote:
			return p.hookCommentVote(token)
		}
	}

	return nil
}
