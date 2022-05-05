// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
)

// convert.go contains the conversion functions for converting git backend
// types into tstore backend and plugin types.

func convertRecordMetadata(r gitbe.RecordMetadata, version uint32) backend.RecordMetadata {
	return backend.RecordMetadata{
		Token:     r.Token,
		Version:   version, // Parsed from git path
		Iteration: uint32(r.Iteration),
		State:     backend.StateVetted,
		Status:    convertMDStatus(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.Merkle,
	}
}

func convertMDStatus(s gitbe.MDStatusT) backend.StatusT {
	switch s {
	case gitbe.MDStatusInvalid:
		return backend.StatusInvalid
	case gitbe.MDStatusUnvetted:
		return backend.StatusUnreviewed
	case gitbe.MDStatusVetted:
		return backend.StatusPublic
	case gitbe.MDStatusCensored:
		return backend.StatusCensored
	case gitbe.MDStatusIterationUnvetted:
		return backend.StatusUnreviewed
	case gitbe.MDStatusArchived:
		return backend.StatusArchived
	default:
		panic(fmt.Sprintf("invalid md status %v", s))
	}
}

func convertFile(payload []byte, fileName string) backend.File {
	return backend.File{
		Name:    fileName, // Parsed from git path
		MIME:    http.DetectContentType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}

func convertProposalMetadata(name string) pi.ProposalMetadata {
	return pi.ProposalMetadata{
		Name:        name, // Parsed from index file
		Amount:      0,
		StartDate:   0,
		EndDate:     0,
		Domain:      "",
		LegacyToken: "", // Populated by the import command
	}
}

func convertVoteMetadata(pm gitbe.ProposalMetadata) ticketvote.VoteMetadata {
	return ticketvote.VoteMetadata{
		LinkBy: pm.LinkBy,
		LinkTo: pm.LinkTo,
	}
}

func convertUserMetadata(pg gitbe.ProposalGeneralV2, userID string) usermd.UserMetadata {
	return usermd.UserMetadata{
		UserID:    userID, // Retrieved from politeia API using public key
		PublicKey: pg.PublicKey,
		Signature: pg.Signature,
	}
}

func convertStatusChange(sc gitbe.RecordStatusChangeV2, token string, version uint32) usermd.StatusChangeMetadata {
	return usermd.StatusChangeMetadata{
		Token:     token,   // Parsed from git path
		Version:   version, // Parsed from git path
		Status:    uint32(convertRecordStatus(sc.NewStatus)),
		Reason:    sc.StatusChangeMessage,
		PublicKey: sc.AdminPubKey,
		// Some signatures may be empty since the signature
		// field is only present on the v2 gitbe status
		// change struct.
		Signature: sc.Signature,
		Timestamp: sc.Timestamp,
	}
}

func convertRecordStatus(r gitbe.RecordStatusT) backend.StatusT {
	switch r {
	case gitbe.RecordStatusNotReviewed:
		return backend.StatusUnreviewed
	case gitbe.RecordStatusCensored:
		return backend.StatusCensored
	case gitbe.RecordStatusPublic:
		return backend.StatusPublic
	case gitbe.RecordStatusUnreviewedChanges:
		return backend.StatusUnreviewed
	case gitbe.RecordStatusArchived:
		return backend.StatusArchived
	}
	panic(fmt.Sprintf("invalid status %v", r))
}

func convertCommentAdd(c gitbe.Comment, userID string) comments.CommentAdd {
	parentID, err := strconv.ParseUint(c.ParentID, 10, 64)
	if err != nil {
		panic(err)
	}
	commentID, err := strconv.ParseUint(c.CommentID, 10, 64)
	if err != nil {
		panic(err)
	}
	return comments.CommentAdd{
		UserID:        userID, // Retrieved from the politeia API by public key
		State:         comments.RecordStateVetted,
		Token:         c.Token,
		ParentID:      uint32(parentID),
		Comment:       c.Comment,
		PublicKey:     c.PublicKey,
		Signature:     c.Signature,
		CommentID:     uint32(commentID),
		Version:       1, // Edits were not allowed on legacy comments
		Timestamp:     c.Timestamp,
		Receipt:       c.Receipt,
		ExtraData:     "", // Intentionally omitted
		ExtraDataHint: "", // Intentionally omitted
	}
}

func convertCommentDel(cc gitbe.CensorComment, parentID uint32, userID string) comments.CommentDel {
	commentID, err := strconv.ParseUint(cc.CommentID, 10, 64)
	if err != nil {
		panic(err)
	}
	return comments.CommentDel{
		Token:     cc.Token,
		State:     comments.RecordStateVetted,
		CommentID: uint32(commentID),
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,
		ParentID:  parentID, // Taken from the parent comment
		UserID:    userID,   // Retrieved from the politeia API by public key
		Timestamp: cc.Timestamp,
		Receipt:   cc.Receipt,
	}
}

func convertCommentVote(lc gitbe.LikeComment, userID string) comments.CommentVote {
	commentID, err := strconv.ParseUint(lc.CommentID, 10, 64)
	if err != nil {
		panic(err)
	}
	var vote comments.VoteT
	switch {
	case lc.Action == "1":
		vote = comments.VoteUpvote
	case lc.Action == "-1":
		vote = comments.VoteDownvote
	default:
		panic("invalid comment vote code")
	}
	return comments.CommentVote{
		UserID:    userID, // Retrieved from the politeia API by public key
		State:     comments.RecordStateVetted,
		Token:     lc.Token,
		CommentID: uint32(commentID),
		Vote:      vote,
		PublicKey: lc.PublicKey,
		Signature: lc.Signature,
		Timestamp: lc.Timestamp,
		Receipt:   lc.Receipt,
	}
}

func convertVoteDetails(startVoteJSON []byte, svr gitbe.StartVoteReply, version uint32, voteMD *ticketvote.VoteMetadata) ticketvote.VoteDetails {
	// The start vote structure has a v1 and v2.
	// The fields that we need are pulled out of
	// the specific structure.
	var (
		token           string
		proposalVersion uint32
		voteType        ticketvote.VoteT
		mask            uint64
		duration        uint32
		quorum          uint32
		pass            uint32
		options         []ticketvote.VoteOption
		publicKey       string
	)
	structVersion, err := decodeVersion(startVoteJSON)
	if err != nil {
		panic(err)
	}
	switch structVersion {
	case 1:
		// Decode the start vote
		var sv gitbe.StartVoteV1
		err = json.Unmarshal(startVoteJSON, &sv)
		if err != nil {
			panic(err)
		}

		// Pull the fields that we need
		token = sv.Vote.Token
		proposalVersion = version
		voteType = ticketvote.VoteTypeStandard
		mask = sv.Vote.Mask
		duration = sv.Vote.Duration
		quorum = sv.Vote.QuorumPercentage
		pass = sv.Vote.PassPercentage
		options = convertVoteOptions(sv.Vote.Options)
		publicKey = sv.PublicKey

	case 2:
		// Decode the start vote
		var sv gitbe.StartVoteV2
		err = json.Unmarshal(startVoteJSON, &sv)
		if err != nil {
			panic(err)
		}

		// Sanity check proposal version. The version in the start vote
		// should be the same version from the proposal directory path.
		if version != sv.Vote.ProposalVersion {
			panic(fmt.Sprintf("start vote version mismatch: %v %v",
				version, sv.Vote.ProposalVersion))
		}

		// Pull the fields that we need
		token = sv.Vote.Token
		proposalVersion = version
		voteType = convertVoteType(sv.Vote.Type)
		mask = sv.Vote.Mask
		duration = sv.Vote.Duration
		quorum = sv.Vote.QuorumPercentage
		pass = sv.Vote.PassPercentage
		options = convertVoteOptions(sv.Vote.Options)
		publicKey = sv.PublicKey

	default:
		panic(fmt.Sprintf("invalid start vote version '%v'", structVersion))
	}

	// Populate parent if it's a RFP submission
	var parent string
	if voteMD != nil {
		parent = voteMD.LinkTo
	}

	startHeight, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
	if err != nil {
		panic(err)
	}
	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 32)
	if err != nil {
		panic(err)
	}

	// The Signature and Receipt have been omitted because the
	// message being signed changes between the git backend and
	// the tstore backend. Transferring the old signature would
	// result in invalid signature errors.
	return ticketvote.VoteDetails{
		Params: ticketvote.VoteParams{
			Token:            token,
			Version:          proposalVersion, // Parsed from git path
			Type:             voteType,
			Mask:             mask,
			Duration:         duration,
			QuorumPercentage: quorum,
			PassPercentage:   pass,
			Options:          options,
			Parent:           parent,
		},
		PublicKey:        publicKey,
		Signature:        "", // Intentionally omitted
		Receipt:          "", // Intentionally omitted
		StartBlockHeight: uint32(startHeight),
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   uint32(endHeight),
		EligibleTickets:  svr.EligibleTickets,
	}
}

func convertVoteOptions(options []gitbe.VoteOption) []ticketvote.VoteOption {
	opts := make([]ticketvote.VoteOption, 0, len(options))
	for _, v := range options {
		opts = append(opts, ticketvote.VoteOption{
			ID:          v.Id,
			Description: v.Description,
			Bit:         v.Bits,
		})
	}
	return opts
}

func convertVoteType(t gitbe.VoteT) ticketvote.VoteT {
	switch t {
	case gitbe.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case gitbe.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	panic(fmt.Sprintf("invalid vote type %v", t))
}

func convertCastVoteDetails(cvj gitbe.CastVoteJournal, address string, timestamp int64) ticketvote.CastVoteDetails {
	return ticketvote.CastVoteDetails{
		Token:     cvj.CastVote.Token,
		Ticket:    cvj.CastVote.Ticket,
		VoteBit:   cvj.CastVote.VoteBit,
		Signature: cvj.CastVote.Signature,
		Address:   address, // Retrieved from dcrdata
		Receipt:   cvj.Receipt,
		// Timestamp will be the timestamp of the git commit that
		// added the vote to the ballots journal. The exact
		// timestamp of when the vote was cast does not exist.
		Timestamp: timestamp,
	}
}

// decodeVersion returns the version field from the provided JSON payload. This
// function should only be used when the payload contains a single struct with
// a "version" field.
func decodeVersion(payload []byte) (uint, error) {
	data := make(map[string]interface{}, 32)
	err := json.Unmarshal(payload, &data)
	if err != nil {
		return 0, err
	}
	version := uint(data["version"].(float64))
	if version == 0 {
		return 0, fmt.Errorf("version not found")
	}
	return version, nil
}
