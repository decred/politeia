// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

// convertRecordMetadata reads the git backend RecordMetadata from disk for
// the provided proposal and converts it to a tstore backend RecordMetadata.
func convertRecordMetadata(proposalDir string) (*backend.RecordMetadata, error) {
	fmt.Printf("  RecordMetadata\n")

	// Read the git backend record metadata from disk
	fp := recordMetadataPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var r gitbe.RecordMetadata
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}

	// The version number can be found in the proposal
	// file path. It is the last directory in the path.
	v := filepath.Base(proposalDir)
	version, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}

	// Build record metadata
	rm := backend.RecordMetadata{
		// We are using the legacy git token as the record
		// metadata token for the sake of keeping certain
		// signatures coherent (I think...). This needs to
		// be verified.
		Token:     r.Token,
		Version:   uint32(version),
		Iteration: uint32(r.Iteration),
		State:     backend.StateVetted,
		Status:    convertMDStatus(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.Merkle,
	}

	fmt.Printf("    Token    : %v\n", rm.Token)
	fmt.Printf("    Version  : %v\n", rm.Version)
	fmt.Printf("    Iteration: %v\n", rm.Iteration)
	fmt.Printf("    State    : %v\n", backend.States[rm.State])
	fmt.Printf("    Status   : %v\n", backend.Statuses[rm.Status])
	fmt.Printf("    Timestamp: %v\n", rm.Timestamp)
	fmt.Printf("    Merkle   : %v\n", rm.Merkle)

	return &rm, nil
}

// convertFiles reads all of the git backend proposal index file and image
// attachments from disk for the provided proposal and converts them to tstore
// backend files.
func convertFiles(proposalDir string) ([]backend.File, error) {
	fmt.Printf("  Files\n")

	files := make([]backend.File, 0, 64)

	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	files = append(files, newFile(b, pi.FileNameIndexFile))

	fmt.Printf("    %v\n", pi.FileNameIndexFile)

	// Read any image attachments from disk
	attachments, err := proposalAttachmentFilenames(proposalDir)
	if err != nil {
		return nil, err
	}
	for _, fn := range attachments {
		fp := attachmentFilePath(proposalDir, fn)
		b, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, err
		}

		files = append(files, newFile(b, fn))

		fmt.Printf("    %v\n", fn)
	}

	return files, nil
}

// convertProposalMetadata reads the git backend data from disk that is
// required to build a pi plugin ProposalMetadata structure, then returns the
// ProposalMetadata.
func convertProposalMetadata(proposalDir string) (*pi.ProposalMetadata, error) {
	fmt.Printf("  Proposal metadata\n")

	// The only data we need to pull from the legacy
	// proposal is the proposal name. The name will
	// always be the first line of the proposal index
	// file.
	name, err := parseProposalName(proposalDir)
	if err != nil {
		return nil, err
	}

	// Get the legacy token from the proposal
	// directory path.
	token, ok := gitProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}

	fmt.Printf("    Name       : %v\n", name)
	fmt.Printf("    LegacyToken: %v\n", token)

	return &pi.ProposalMetadata{
		Name:        name,
		Amount:      0,
		StartDate:   0,
		EndDate:     0,
		Domain:      "",
		LegacyToken: token,
	}, nil
}

// convertVoteMetadata reads the git backend data from disk that is
// required to build a ticketvote plugin VoteMetadata structure, then
// returns the VoteMetadata.
func convertVoteMetadata(proposalDir string) (*ticketvote.VoteMetadata, error) {
	fmt.Printf("  Vote metadata\n")

	// The vote metadata fields are in the gitbe
	// proposal metadata payload file. This file
	// will only exist for some gitbe proposals.
	fp := proposalMetadataPath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Read the proposal metadata file from disk
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var pm gitbe.ProposalMetadata
	err = json.Unmarshal(b, &pm)
	if err != nil {
		return nil, err
	}

	// Build the vote metadata
	vm := ticketvote.VoteMetadata{
		LinkBy: pm.LinkBy,
		LinkTo: pm.LinkTo,
	}

	fmt.Printf("    Link by: %v\n", vm.LinkBy)
	fmt.Printf("    Link to: %v\n", vm.LinkTo)

	return &vm, nil
}

// convertUserMetadata reads the git backend data from disk that is required to
// build a usermd plugin UserMetadata structure, then returns the UserMetadata.
//
// This function makes an external API call to the politeia API to retrieve the
// user ID.
func (c *convertCmd) convertUserMetadata(proposalDir string) (*usermd.UserMetadata, error) {
	fmt.Printf("  User metadata\n")

	// Read the proposal general mdstream from disk
	fp := proposalGeneralPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// We can decode both the v1 and v2 proposal general
	// metadata stream into the ProposalGeneralV2 struct
	// since the fields we need from it are present in
	// both versions.
	var p gitbe.ProposalGeneralV2
	err = json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}

	// Populate the user ID. The user ID was not saved
	// to disk in the git backend, so we must retrieve
	// it from the politeia API using the public key.
	userID, err := c.getUserIDByPubKey(p.PublicKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("    User ID  : %v\n", userID)
	fmt.Printf("    PublicKey: %v\n", p.PublicKey)
	fmt.Printf("    Signature: %v\n", p.Signature)

	return &usermd.UserMetadata{
		UserID:    userID,
		PublicKey: p.PublicKey,
		Signature: p.Signature,
	}, nil
}

// convertStatusChange reads the git backend data from disk that is
// required to build the usermd plugin StatusChangeMetadata structures,
// then returns the latest StateChangeMetadata.
//
// Only the most recent status change is returned.
func convertStatusChange(proposalDir string) (*usermd.StatusChangeMetadata, error) {
	fmt.Printf("  Status changes\n")

	// Read the status changes mdstream from disk
	fp := statusChangesPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// Parse the token and version from the proposal dir path
	token, ok := gitProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}
	version, err := proposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// The git backend v1 status change struct does not have the
	// signature included. This is the only difference between
	// v1 and v2, so we decode all of them into the v2 structure.
	var (
		statuses = make([]usermd.StatusChangeMetadata, 0, 16)
		decoder  = json.NewDecoder(bytes.NewReader(b))
	)
	for {
		var sc gitbe.RecordStatusChangeV2
		err := decoder.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		status := convertRecordStatus(sc.NewStatus)
		scm := usermd.StatusChangeMetadata{
			Token:     token,
			Version:   version,
			Status:    uint32(status),
			Reason:    sc.StatusChangeMessage,
			PublicKey: sc.AdminPubKey,
			Signature: sc.Signature, // Only present on v2
			Timestamp: sc.Timestamp,
		}

		statuses = append(statuses, scm)
	}

	// Sort status changes from oldest to newest
	sort.SliceStable(statuses, func(i, j int) bool {
		return statuses[i].Timestamp < statuses[j].Timestamp
	})

	// Only the most recent status change is returned
	latest := statuses[len(statuses)-1]

	status := backend.StatusT(latest.Status)
	fmt.Printf("    Token    : %v\n", latest.Token)
	fmt.Printf("    Version  : %v\n", latest.Version)
	fmt.Printf("    Status   : %v\n", backend.Statuses[status])
	fmt.Printf("    PublicKey: %v\n", latest.PublicKey)
	fmt.Printf("    Signature: %v\n", latest.Signature)
	fmt.Printf("    Reason   : %v\n", latest.Reason)
	fmt.Printf("    Timestamp: %v\n", latest.Timestamp)

	return &latest, nil
}

// convertAuthDetails reads the git backend data from disk that is
// required to build a ticketvote plugin AuthDetails structure, then
// returns the AuthDetails.
func convertAuthDetails(proposalDir string, recordMD *backend.RecordMetadata) (*ticketvote.AuthDetails, error) {
	fmt.Printf("  AuthDetails\n")

	// One censored legacy proposal has an empty vote details, it shouldn't be
	// imported to tstore as we don't delete all of the proposal's data once it
	// censored.
	if recordMD.Status == backend.StatusArchived {
		return nil, nil
	}

	// Verify that an authorize vote mdstream exists.
	// This will not exist for some proposals, e.g.
	// abandoned proposals.
	fp := authorizeVotePath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Read the authorize vote mdstream from disk
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	var av gitbe.AuthorizeVote
	err = json.Unmarshal(b, &av)
	if err != nil {
		return nil, err
	}

	// Parse the token and version from the proposal dir path
	token, ok := gitProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}
	if av.Token != token {
		return nil, fmt.Errorf("auth vote token invalid: got %v, want %v",
			av.Token, token)
	}
	version, err := proposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// Build the ticketvote AuthDetails
	ad := ticketvote.AuthDetails{
		Token:     av.Token,
		Version:   version,
		Action:    av.Action,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
		Timestamp: av.Timestamp,
		Receipt:   av.Receipt,
	}

	// Verify signatures
	adv1 := convertAuthDetailsToV1(ad)
	err = client.AuthDetailsVerify(adv1, gitbe.PublicKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("    Action: %v\n", ad.Action)

	return &ad, nil
}

// convertVoteDetails reads the git backend data from disk that is
// required to build a ticketvote plugin VoteDetails structure, then
// returns the VoteDetails.
func convertVoteDetails(proposalDir string, voteMD *ticketvote.VoteMetadata) (*ticketvote.VoteDetails, error) {
	fmt.Printf("  Vote details\n")

	// Verify that vote mdstreams exists. These
	// will not exist for some proposals, such
	// as abandoned proposals.
	fp := startVotePath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Pull the proposal version from the proposal dir path
	version, err := proposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// Read the start vote mdstream from disk
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// The start vote structure has a v1 and v2. The fields
	// that we need are pulled out of the specific structure.
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
	structVersion, err := decodeVersion(b)
	if err != nil {
		return nil, err
	}
	switch structVersion {
	case 1:
		// Decode the start vote
		var sv gitbe.StartVoteV1
		err = json.Unmarshal(b, &sv)
		if err != nil {
			return nil, err
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
		err = json.Unmarshal(b, &sv)
		if err != nil {
			return nil, err
		}

		// Sanity check proposal version. The version in the start vote
		// should be the same version from the proposal directory path.
		if version != sv.Vote.ProposalVersion {
			return nil, fmt.Errorf("start vote version mismatch: %v %v",
				version, sv.Vote.ProposalVersion)
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
		return nil, fmt.Errorf("invalid start vote version '%v'",
			structVersion)
	}

	// Populate parent if it's a RFP submission
	var parent string
	if voteMD != nil {
		parent = voteMD.LinkTo
	}

	// Read the start vote reply from disk
	fp = startVoteReplyPath(proposalDir)
	b, err = ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	var svr gitbe.StartVoteReply
	err = json.Unmarshal(b, &svr)
	if err != nil {
		return nil, err
	}

	startHeight, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
	if err != nil {
		return nil, err
	}
	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 32)
	if err != nil {
		return nil, err
	}

	// Build the ticketvote VoteDetails
	vd := ticketvote.VoteDetails{
		Params: ticketvote.VoteParams{
			Token:            token,
			Version:          proposalVersion,
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

	fmt.Printf("    Start height: %v\n", vd.StartBlockHeight)
	fmt.Printf("    Start hash  : %v\n", vd.StartBlockHash)
	fmt.Printf("    End height  : %v\n", vd.EndBlockHeight)
	fmt.Printf("    Duration    : %v\n", vd.Params.Duration)
	fmt.Printf("    Quorum      : %v\n", vd.Params.QuorumPercentage)
	fmt.Printf("    Pass        : %v\n", vd.Params.PassPercentage)
	fmt.Printf("    Type        : %v\n", vd.Params.Type)
	fmt.Printf("    Parent      : %v\n", vd.Params.Parent)

	return &vd, nil
}

// convertVoteOptions converts the given git backend vote options to
// ticketvote plugin vote options.
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

// convertVoteType converts a git backend vote type to a ticketvote plugin
// vote type.
func convertVoteType(t gitbe.VoteT) ticketvote.VoteT {
	switch t {
	case gitbe.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case gitbe.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	panic(fmt.Sprintf("invalid vote type %v", t))
}

// convertCastVotes reads the git backend data from disk that is
// required to build the ticketvote plugin CastVoteDetails structures,
// then returns the CastVoteDetails slice.
func convertCastVotes(proposalDir string, skipBallots bool, limit int) ([]ticketvote.CastVoteDetails, error) {
	fmt.Printf("  Cast votes\n")

	var castVotes []ticketvote.CastVoteDetails
	if skipBallots {
		return castVotes, nil
	}

	// Verify that the ballots journal exists. This
	/// will not exist for some proposals, such as
	// abandoned proposals.
	fp := ballotsJournalPath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Open the ballots journal
	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the journal line-by-line
	var (
		// There are some duplicate votes in early proposals due to
		// a bug. Use a map here so that duplicate votes are removed.
		//
		// map[token]CastVoteDetails
		votes = make(map[string]ticketvote.CastVoteDetails, 40960)

		scanner = bufio.NewScanner(f)
		count   int
	)
	for scanner.Scan() {
		count++

		// Decode the current line
		cvj, err := decodeBallotJournalLine(scanner.Bytes())
		if err != nil {
			return nil, err
		}

		// Build the cast vote
		cvd := ticketvote.CastVoteDetails{
			Token:     cvj.CastVote.Token,
			Ticket:    cvj.CastVote.Ticket,
			VoteBit:   cvj.CastVote.VoteBit,
			Signature: cvj.CastVote.Signature,
			Receipt:   cvj.Receipt,
		}

		// Save the cast vote
		votes[cvd.Ticket] = cvd

		printInPlace(fmt.Sprintf("    Vote %v", count))

		// If the number of converted cast votes hits the limit, we are done
		if len(votes) == limit {
			break
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n")

	// Put the votes into a slice and sort them by timestamp,
	// from oldest to newest.
	castVotes = make([]ticketvote.CastVoteDetails, 0, len(votes))
	for _, vote := range votes {
		castVotes = append(castVotes, vote)
	}
	sort.SliceStable(castVotes, func(i, j int) bool {
		return castVotes[i].Timestamp < castVotes[j].Timestamp
	})

	return castVotes, nil
}

// convertCastVoteDetailsToV1 is used to verify the cast vote details signature
// through the www client.
func convertCastVoteDetailsToV1(vote ticketvote.CastVoteDetails) v1.CastVoteDetails {
	return v1.CastVoteDetails{
		Token:     vote.Token,
		Ticket:    vote.Ticket,
		VoteBit:   vote.VoteBit,
		Address:   vote.Address,
		Signature: vote.Signature,
		Receipt:   vote.Receipt,
		Timestamp: vote.Timestamp,
	}
}

// decodeBallotJournalLine decodes a line from a proposal's ballot journal. The
// line will contain two JSON structures. The JournalAction structure and the
// CastVoteJournal structure.
func decodeBallotJournalLine(line []byte) (*gitbe.CastVoteJournal, error) {
	r := bytes.NewReader(line)
	d := json.NewDecoder(r)

	// Decode the action
	var j gitbe.JournalAction
	err := d.Decode(&j)
	if err != nil {
		return nil, err
	}
	if j.Action != gitbe.JournalActionAdd {
		return nil, fmt.Errorf("invalid action '%v'", j.Action)
	}

	// Decode the cast vote
	var cvj gitbe.CastVoteJournal
	err = d.Decode(&cvj)
	if err != nil {
		return nil, err
	}

	return &cvj, nil
}

// commentTypes includes proposal's comments data
type commentTypes struct {
	Adds  []comments.CommentAdd
	Dels  []comments.CommentDel
	Votes []comments.CommentVote
}

// convertComments reads and converts the proposal's comments data located in
// the given proposal dir.
func (c *convertCmd) convertComments(proposalDir string) (*commentTypes, error) {
	// If skip comments flag is on, noting to do
	if c.skipComments {
		return &commentTypes{}, nil
	}

	path := commentsJournalPath(proposalDir)

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return nil, err
	}

	var (
		parentIDs = make(map[uint32]uint32)

		// There are some duplicates in the comment data, we store each
		// type in a map to with the signatures as keys to avoid duplicates.
		mAdds  = make(map[string]comments.CommentAdd)  // map[signature]CommentAdd
		mDels  = make(map[string]comments.CommentDel)  // map[signature]CommentDel
		mVotes = make(map[string]comments.CommentVote) // map[signature]CommentVote
	)

	s := bufio.NewScanner(fh)
	for i := 0; s.Scan(); i++ {
		ss := bytes.NewReader([]byte(s.Text()))
		d := json.NewDecoder(ss)

		var action gitbe.JournalAction
		err := d.Decode(&action)
		if err != nil {
			return nil, err
		}

		switch action.Action {
		case gitbe.JournalActionAdd:
			ca, err := c.convertCommentAdd(d)
			if err != nil {
				return nil, err
			}

			// Append add blob.
			mAdds[ca.Signature] = *ca

			// Store comment's parent ID
			parentIDs[ca.CommentID] = ca.ParentID

		case gitbe.JournalActionDel:
			cd, err := c.convertCommentDel(d, parentIDs)
			if err != nil {
				return nil, err
			}

			// Append del blob.
			mDels[cd.Signature] = *cd

		case gitbe.JournalActionAddLike:
			cv, err := c.convertCommentAddLike(d)
			if err != nil {
				return nil, err
			}

			// Append vote blob.
			mVotes[cv.Signature] = *cv

		default:
			return nil, err
		}
	}

	// Convert maps to slices.
	var (
		adds  = make([]comments.CommentAdd, 0, len(mAdds))
		dels  = make([]comments.CommentDel, 0, len(mDels))
		votes = make([]comments.CommentVote, 0, len(mVotes))
	)
	for _, add := range mAdds {
		adds = append(adds, add)
	}
	for _, del := range mDels {
		dels = append(dels, del)
	}
	for _, vote := range mVotes {
		votes = append(votes, vote)
	}

	return &commentTypes{
		Adds:  adds,
		Dels:  dels,
		Votes: votes,
	}, nil
}

// convertCommentAdd decodes the given gitbe comment add, then converts it to
// a tstore comment add.
func (c *convertCmd) convertCommentAdd(d *json.Decoder) (*comments.CommentAdd, error) {
	var cm decredplugin.Comment
	err := d.Decode(&cm)
	if err != nil {
		return nil, err
	}

	// Get user ID
	userID, err := c.getUserIDByPubKey(cm.PublicKey)
	if err != nil {
		return nil, err
	}

	// Parse IDs.
	pid, err := strconv.Atoi(cm.ParentID)
	if err != nil {
		return nil, err
	}
	cid, err := strconv.Atoi(cm.CommentID)
	if err != nil {
		return nil, err
	}

	// Append add blob.
	return &comments.CommentAdd{
		UserID:    userID,
		State:     comments.RecordStateVetted,
		Token:     cm.Token,
		ParentID:  uint32(pid),
		Comment:   cm.Comment,
		PublicKey: cm.PublicKey,
		Signature: cm.Signature,
		CommentID: uint32(cid),
		Version:   1,
		Timestamp: cm.Timestamp,
		Receipt:   cm.Receipt,
	}, nil
}

// convertCommentDel decodes the given gitbe comment del, then converts it to
// a tstore comment del.
func (c *convertCmd) convertCommentDel(d *json.Decoder, parentIDs map[uint32]uint32) (*comments.CommentDel, error) {
	var cc decredplugin.CensorComment
	err := d.Decode(&cc)
	if err != nil {
		return nil, err
	}

	// Get user ID
	userID, err := c.getUserIDByPubKey(cc.PublicKey)
	if err != nil {
		return nil, err
	}

	// Parse IDs.
	commentID, err := strconv.Atoi(cc.CommentID)
	if err != nil {
		return nil, err
	}
	parentID := parentIDs[uint32(commentID)]

	// Append del blob.
	return &comments.CommentDel{
		Token:     cc.Token,
		State:     comments.RecordStateVetted,
		CommentID: uint32(commentID),
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,
		ParentID:  parentID,
		UserID:    userID,
		Timestamp: cc.Timestamp,
		Receipt:   cc.Receipt,
	}, nil
}

// convertCommentAddLike decodes the given gitbe comment like, then converts
// it to a tstore comment vote.
func (c *convertCmd) convertCommentAddLike(d *json.Decoder) (*comments.CommentVote, error) {
	var lc gitbe.LikeComment
	err := d.Decode(&lc)
	if err != nil {
		return nil, err
	}

	// Get user ID
	userID, err := c.getUserIDByPubKey(lc.PublicKey)
	if err != nil {
		return nil, err
	}

	// Parse comment ID.
	cid, err := strconv.Atoi(lc.CommentID)
	if err != nil {
		return nil, err
	}

	// Parse comment vote.
	var vote comments.VoteT
	switch {
	case lc.Action == "1":
		vote = comments.VoteUpvote
	case lc.Action == "-1":
		vote = comments.VoteDownvote
	default:
		return nil, fmt.Errorf("invalid comment vote code")
	}

	return &comments.CommentVote{
		UserID:    userID,
		State:     comments.RecordStateVetted,
		Token:     lc.Token,
		CommentID: uint32(cid),
		Vote:      vote,
		PublicKey: lc.PublicKey,
		Signature: lc.Signature,
		Timestamp: lc.Timestamp,
		Receipt:   lc.Receipt,
	}, nil
}

// convertMDStatus converts a gitbe record metadata status to a tstore record
// status.
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

// convertRecordStatus covnerts a gitbe record status to a tstore record
// status.
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

// convertAuthDetailsToV1 converts a ticketvote plugin AuthDetails to a
// legacy AuthDetails.
func convertAuthDetailsToV1(a ticketvote.AuthDetails) v1.AuthDetails {
	return v1.AuthDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    a.Action,
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: a.Timestamp,
		Receipt:   a.Receipt,
	}
}

// recordMetadataPath returns the proposal's record metadata file path
func recordMetadataPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordMetadataFilename)
}

// payloadDirPath returns the proposal's record payload sub dir path
func payloadDirPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordPayloadPath)
}

// indexFilePath returns the propsoal's index file path
func indexFilePath(proposalDir string) string {
	return filepath.Join(payloadDirPath(proposalDir), gitbe.IndexFilename)
}

// attachmentFilePath returns the proposal's attachment file path
func attachmentFilePath(proposalDir, attachmentFilename string) string {
	return filepath.Join(payloadDirPath(proposalDir), attachmentFilename)
}

// proposalMetadataPath returns the proposal's metadata file path
func proposalMetadataPath(proposalDir string) string {
	return filepath.Join(payloadDirPath(proposalDir),
		gitbe.ProposalMetadataFilename)
}

// proposalGeneralPath returns the proposal's general mdstream file path
func proposalGeneralPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamProposalGeneral)
}

// statusChangesPath returns the proposal's status changes mdstream file path
func statusChangesPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStatusChanges)
}

// authorizeVotePath returns the proposal's vote auths mdstream file path
func authorizeVotePath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamAuthorizeVote)
}

// startVotePath returns the proposal's start vote mdstream file path
func startVotePath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStartVote)
}

// startVoteReplyPath returns the proposal's start vote mdstream file path
func startVoteReplyPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStartVoteReply)
}

// decredPluginPath returns the proposal's decred plugin sub dir path
func decredPluginPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.DecredPluginPath)
}

// ballotsJournalPath returns the proposal's ballots journal file path
func ballotsJournalPath(proposalDir string) string {
	return filepath.Join(decredPluginPath(proposalDir),
		gitbe.BallotJournalFilename)
}

// commentsJournalPath returns the proposal's comments journal file path
func commentsJournalPath(proposalDir string) string {
	return filepath.Join(decredPluginPath(proposalDir),
		gitbe.CommentsJournalFilename)
}

// parseProposalName parses and returns the proposal name from the proposal
// index file.
func parseProposalName(proposalDir string) (string, error) {
	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", err
	}

	// Parse the proposal name from the index file. The
	// proposal name will always be the first line of the
	// file.
	r := bufio.NewReader(bytes.NewReader(b))
	name, _, err := r.ReadLine()
	if err != nil {
		return "", err
	}

	return string(name), nil
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

// newFile returns a new backend file.
func newFile(payload []byte, fileName string) backend.File {
	return backend.File{
		Name:    fileName,
		MIME:    http.DetectContentType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}
