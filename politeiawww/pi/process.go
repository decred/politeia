// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"
	"encoding/json"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func (p *Pi) proposals(ctx context.Context, state string, reqs []pdv1.RecordRequest) (map[string]v1.Proposal, error) {
	var (
		records map[string]pdv1.Record
		err     error
	)
	switch state {
	case v1.ProposalStateUnvetted:
		records, err = p.politeiad.GetUnvettedBatch(ctx, reqs)
		if err != nil {
			return nil, err
		}
	case v1.ProposalStateVetted:
		records, err = p.politeiad.GetVettedBatch(ctx, reqs)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid state %v", state)
	}

	proposals := make(map[string]v1.Proposal, len(records))
	for k, v := range records {
		// Convert to a proposal
		pr, err := convertRecord(v, state)
		if err != nil {
			return nil, err
		}

		// Fill in user data
		userID := userIDFromMetadataStreamsPD(v.Metadata)
		uid, err := uuid.Parse(userID)
		if err != nil {
			return nil, err
		}
		u, err := p.userdb.UserGetById(uid)
		if err != nil {
			return nil, err
		}
		proposalPopulateUserData(pr, *u)

		proposals[k] = *pr
	}

	return proposals, nil
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

	// Setup record requests. We don't retrieve any index files or
	// attachment files in order to keep the payload size minimal.
	reqs := make([]pdv1.RecordRequest, 0, len(ps.Tokens))
	for _, v := range ps.Tokens {
		reqs = append(reqs, pdv1.RecordRequest{
			Token: v,
			Filenames: []string{
				v1.FileNameProposalMetadata,
				v1.FileNameVoteMetadata,
			},
		})
	}

	// Get proposals
	proposals, err := p.proposals(ctx, ps.State, reqs)
	if err != nil {
		return nil, err
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
func userMetadataDecodePD(ms []pdv1.MetadataStream) (*usermd.UserMetadata, error) {
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
func userIDFromMetadataStreamsPD(ms []pdv1.MetadataStream) string {
	um, err := userMetadataDecodePD(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}
