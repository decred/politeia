// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// proposal returns a version of a proposal record from politeiad. If version
// is an empty string then the most recent version will be returned.
func (p *Pi) proposal(ctx context.Context, state, token, version string) (*v1.Proposal, error) {
	var (
		r   *pdv1.Record
		err error
	)
	switch state {
	case v1.ProposalStateUnvetted:
		r, err = p.politeiad.GetUnvetted(ctx, token, version)
		if err != nil {
			return nil, err
		}
	case v1.ProposalStateVetted:
		r, err = p.politeiad.GetVetted(ctx, token, version)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid state %v", state)
	}

	// Convert to a proposal
	pr, err := convertRecord(*r, state)
	if err != nil {
		return nil, err
	}

	// Fill in user data
	userID := userIDFromMetadataStreams(r.Metadata)
	uid, err := uuid.Parse(userID)
	u, err := p.userdb.UserGetById(uid)
	if err != nil {
		return nil, err
	}
	proposalPopulateUserData(pr, *u)

	return pr, nil
}

func (p *Pi) processProposals(ctx context.Context, ps v1.Proposals, u *user.User) (*v1.ProposalsReply, error) {
	log.Tracef("processProposals: %v %v", ps.State, ps.Tokens)

	// Verify state
	switch ps.State {
	case v1.ProposalStateUnvetted, v1.ProposalStateVetted:
		// Allowed; continue
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeProposalStateInvalid,
		}
	}

	// Verify page size
	if len(ps.Tokens) > v1.ProposalsPageSize {
		e := fmt.Sprintf("max page size is %v", v1.ProposalsPageSize)
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePageSizeExceeded,
			ErrorContext: e,
		}
	}

	// Get all proposals in the batch. This should be a batched call to
	// politeiad, but the politeiad API does not provided a batched
	// records endpoint.
	proposals := make(map[string]v1.Proposal, len(ps.Tokens))
	for _, v := range ps.Tokens {
		pr, err := p.proposal(ctx, ps.State, v, "")
		if err != nil {
			// If any error occured simply skip this proposal. It will not
			// be included in the reply.
			continue
		}

		// The only files that are returned in this call are the
		// ProposalMetadata and the VoteMetadata files.
		files := make([]v1.File, 0, len(pr.Files))
		for k := range pr.Files {
			switch pr.Files[k].Name {
			case v1.FileNameProposalMetadata, v1.FileNameVoteMetadata:
				// Include file
				files = append(files, pr.Files[k])
			default:
				// All other files are disregarded. Do nothing.
			}
		}

		pr.Files = files

		proposals[pr.CensorshipRecord.Token] = *pr
	}

	// Only admins and the proposal author are allowed to retrieve
	// unvetted files. Remove files if the user is not an admin or the
	// author. This is a public route so a user may not be present.
	if ps.State == v1.ProposalStateUnvetted {
		for k, v := range proposals {
			var (
				isAuthor = u != nil && u.ID.String() == v.UserID
				isAdmin  = u != nil && u.Admin
			)
			if !isAuthor && !isAdmin {
				v.Files = []v1.File{}
				proposals[k] = v
			}
		}
	}

	return &v1.ProposalsReply{
		Proposals: proposals,
	}, nil
}

// proposalName parses the proposal name from the ProposalMetadata and returns
// it. An empty string will be returned if any errors occur or if a name is not
// found.
func proposalName(r pdv1.Record) string {
	var name string
	for _, v := range r.Files {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			var pm pi.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return ""
			}
			name = pm.Name
		}
	}
	return name
}

// proposalPopulateUserData populates a proposal with user data that is stored
// in the user database and not in politeiad.
func proposalPopulateUserData(pr *v1.Proposal, u user.User) {
	pr.Username = u.Username
}

func convertStatus(s pdv1.RecordStatusT) v1.PropStatusT {
	switch s {
	case pdv1.RecordStatusNotFound:
		// Intentionally omitted. No corresponding PropStatusT.
	case pdv1.RecordStatusNotReviewed:
		return v1.PropStatusUnreviewed
	case pdv1.RecordStatusCensored:
		return v1.PropStatusCensored
	case pdv1.RecordStatusPublic:
		return v1.PropStatusPublic
	case pdv1.RecordStatusUnreviewedChanges:
		return v1.PropStatusUnreviewed
	case pdv1.RecordStatusArchived:
		return v1.PropStatusAbandoned
	}
	return v1.PropStatusInvalid
}

func statusChangesDecode(payload []byte) ([]usermd.StatusChangeMetadata, error) {
	statuses := make([]usermd.StatusChangeMetadata, 0, 16)
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc usermd.StatusChangeMetadata
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

func convertRecord(r pdv1.Record, state string) (*v1.Proposal, error) {
	// Decode metadata streams
	var (
		um  usermd.UserMetadata
		sc  = make([]usermd.StatusChangeMetadata, 0, 16)
		err error
	)
	for _, v := range r.Metadata {
		switch v.ID {
		case usermd.MDStreamIDUserMetadata:
			err = json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
		case usermd.MDStreamIDStatusChanges:
			sc, err = statusChangesDecode([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert files
	files := make([]v1.File, 0, len(r.Files))
	for _, v := range r.Files {
		files = append(files, v1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}

	// Convert statuses
	statuses := make([]v1.StatusChange, 0, len(sc))
	for _, v := range sc {
		statuses = append(statuses, v1.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    v1.PropStatusT(v.Status),
			Reason:    v.Reason,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
		})
	}

	// Some fields are intentionally omitted because they are user data
	// that is not saved to politeiad and needs to be pulled from the
	// user database.
	return &v1.Proposal{
		Version:   r.Version,
		Timestamp: r.Timestamp,
		State:     state,
		Status:    convertStatus(r.Status),
		UserID:    um.UserID,
		Username:  "", // Intentionally omitted
		PublicKey: um.PublicKey,
		Signature: um.Signature,
		Statuses:  statuses,
		Files:     files,
		CensorshipRecord: v1.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}, nil
}

// userMetadataDecode decodes and returns the UserMetadata from the provided
// metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(ms []pdv1.MetadataStream) (*usermd.UserMetadata, error) {
	var userMD *usermd.UserMetadata
	for _, v := range ms {
		if v.ID == usermd.MDStreamIDUserMetadata {
			var um usermd.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
			userMD = &um
			break
		}
	}
	return userMD, nil
}

// userIDFromMetadataStreams searches for a UserMetadata and parses the user ID
// from it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadataStreams(ms []pdv1.MetadataStream) string {
	um, err := userMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}
