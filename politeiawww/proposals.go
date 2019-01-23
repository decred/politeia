// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

// proposalStats is used to provide a summary of the number of proposals
// grouped by proposal status.
type proposalsSummary struct {
	Invalid           int
	NotReviewed       int
	Censored          int
	Public            int
	UnreviewedChanges int
	Abandoned         int
}

// proposalsFilter is used to pass filtering parameters into the filterProps
// function.
type proposalsFilter struct {
	After    string
	Before   string
	UserID   string
	StateMap map[www.PropStateT]bool
}

// getProp gets the most recent verions of the given proposal from the cache
// then fills in any missing fields before returning the proposal.
func (b *backend) getProp(token string) (*www.ProposalRecord, error) {
	log.Tracef("getProp: %v", token)

	r, err := b.cache.Record(token)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Find the number of comments for the proposal
	dc, err := b.decredGetComments(token)
	if err != nil {
		log.Errorf("getProp: decredGetComments failed "+
			"for token %v", token)
	}
	pr.NumComments = uint(len(dc))

	b.RLock()
	defer b.RUnlock()

	// Fill in proposal author info
	userID, ok := b.userPubkeys[pr.PublicKey]
	if !ok {
		log.Errorf("getProp: userID lookup failed for "+
			"token:%v pubkey:%v", token, pr.PublicKey)
	}
	pr.UserId = userID
	pr.Username = b.getUsernameById(userID)

	return &pr, nil
}

// getPropVersion gets a specific version of a proposal from the cache then
// fills in any misssing fields before returning the proposal.
func (b *backend) getPropVersion(token, version string) (*www.ProposalRecord, error) {
	log.Tracef("getPropVersion: %v %v", token, version)

	r, err := b.cache.RecordVersion(token, version)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Fetch number of comments for proposal from cache
	dc, err := b.decredGetComments(token)
	if err != nil {
		log.Errorf("getPropVersion: decredGetComments "+
			"failed for token %v", token)
	}
	pr.NumComments = uint(len(dc))

	b.RLock()
	defer b.RUnlock()

	// Fill in proposal author info
	userID, ok := b.userPubkeys[pr.PublicKey]
	if !ok {
		log.Errorf("getPropVersion: user not found for "+
			"pubkey:%v token:%v", pr.PublicKey, token)
	}
	pr.UserId = userID
	pr.Username = b.getUsernameById(userID)

	return &pr, nil
}

// getAllProps gets the latest version of all proposals from the cache then
// fills any missing fields before returning the proposals.
func (b *backend) getAllProps() ([]www.ProposalRecord, error) {
	log.Tracef("getAllProps")

	// Get proposals from cache
	records, err := b.cache.Inventory()
	if err != nil {
		return nil, err
	}

	// Fill in the number of comments for each proposal
	props := make([]www.ProposalRecord, 0, len(records))
	for _, v := range records {
		p := convertPropFromCache(v)

		dc, err := b.decredGetComments(p.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("getAllProps: decredGetComments failed "+
				"for token %v", p.CensorshipRecord.Token)
		}
		p.NumComments = uint(len(dc))

		props = append(props, p)
	}

	b.RLock()
	defer b.RUnlock()

	// Fill in author info for each proposal. Cache usernames to
	// prevent duplicate database lookups.
	usernames := make(map[string]string, len(props)) // [userID]username
	for i, p := range props {
		userID, ok := b.userPubkeys[p.PublicKey]
		if !ok {
			log.Errorf("getAllProps: userID lookup failed for "+
				"token:%v pubkey:%v", p.CensorshipRecord.Token,
				p.PublicKey)
		}
		p.UserId = userID

		u, ok := usernames[userID]
		if !ok {
			u = b.getUsernameById(userID)
			usernames[userID] = u
		}
		p.Username = u

		props[i] = p
	}

	return props, nil
}

// filterProps filters the given proposals according to the filtering
// parameters specified by the passed in proposalsFilter.  filterProps will
// only return a single page of proposals regardless of how many proposals are
// passed in.
func filterProps(filter proposalsFilter, all []www.ProposalRecord) []www.ProposalRecord {
	log.Tracef("filterProps")

	sort.Slice(all, func(i, j int) bool {
		// Sort by older timestamp first, if timestamps are different
		// from each other
		if all[i].Timestamp != all[j].Timestamp {
			return all[i].Timestamp < all[j].Timestamp
		}

		// Otherwise sort by token
		return all[i].CensorshipRecord.Token >
			all[j].CensorshipRecord.Token
	})

	// pageStarted stores whether or not it's okay to start adding
	// proposals to the array. If the after or before parameter is
	// supplied, we must find the beginning (or end) of the page first.
	pageStarted := (filter.After == "" && filter.Before == "")
	beforeIdx := -1
	proposals := make([]www.ProposalRecord, 0, len(all))

	// Iterate in reverse order because they're sorted by oldest
	// timestamp first.
	for i := len(all) - 1; i >= 0; i-- {
		proposal := all[i]

		// Filter by user if it's provided.
		if (filter.UserID != "") && (filter.UserID != proposal.UserId) {
			continue
		}

		// Filter by the state.
		if val, ok := filter.StateMap[proposal.State]; !ok || !val {
			continue
		}

		if pageStarted {
			proposals = append(proposals, proposal)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		} else if filter.After != "" {
			// The beginning of the page has been found, so
			// the next public proposal is added.
			pageStarted = proposal.CensorshipRecord.Token == filter.After
		} else if filter.Before != "" {
			// The end of the page has been found, so we'll
			// have to iterate in the other direction to
			// add the proposals; save the current index.
			if proposal.CensorshipRecord.Token == filter.Before {
				beforeIdx = i
				break
			}
		}
	}

	// If beforeIdx is set, the caller is asking for vetted proposals
	// whose last result is before the provided proposal.
	if beforeIdx >= 0 {
		for _, proposal := range all[beforeIdx+1:] {
			// Filter by user if it's provided.
			if (filter.UserID != "") && (filter.UserID != proposal.UserId) {
				continue
			}

			// Filter by the state.
			if val, ok := filter.StateMap[proposal.State]; !ok || !val {
				continue
			}

			// The iteration direction is oldest -> newest,
			// so proposals are prepended to the array so
			// the result will be newest -> oldest.
			proposals = append([]www.ProposalRecord{proposal},
				proposals...)
			if len(proposals) >= www.ProposalListPageSize {
				break
			}
		}
	}

	return proposals
}

// getUserProps gets the latest version of all proposals from the cache and
// then filters the proposals according to the specified proposalsFilter, which
// is required to contain a userID.  In addition to a page of filtered user
// proposals, this function also returns summary statistics for all of the
// proposals that the user has submitted grouped by proposal status.
func (b *backend) getUserProps(filter proposalsFilter) ([]www.ProposalRecord, *proposalsSummary, error) {
	log.Tracef("getUserProps: %v", filter.UserID)

	if filter.UserID == "" {
		return nil, nil, fmt.Errorf("filter missing userID")
	}

	// Get the latest version of all proposals from the cache
	all, err := b.getAllProps()
	if err != nil {
		return nil, nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Find proposal summary statistics for the user. This
	// includes statistics on ALL of the proposals that the user
	// has submitted. Not just the single page of proposals that
	// is going to be returned.
	var ps proposalsSummary
	for _, v := range all {
		if v.UserId != filter.UserID {
			continue
		}
		switch v.Status {
		case www.PropStatusNotReviewed:
			ps.NotReviewed++
		case www.PropStatusCensored:
			ps.Censored++
		case www.PropStatusPublic:
			ps.Public++
		case www.PropStatusUnreviewedChanges:
			ps.UnreviewedChanges++
		case www.PropStatusAbandoned:
			ps.Abandoned++
		default:
			ps.Invalid++
		}
	}

	// Filter proposals according to the proposalsFilter. Only
	// a single page of proposals will be returned.
	filtered := filterProps(filter, all)

	return filtered, &ps, nil
}

func (b *backend) getPropComments(token string) ([]www.Comment, error) {
	log.Tracef("getPropComments: %v", token)

	dc, err := b.decredGetComments(token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	b.RLock()
	defer b.RUnlock()

	// Fill in politeiawww data. Cache usernames to reduce
	// database lookups.
	comments := make([]www.Comment, 0, len(dc))
	usernames := make(map[string]string, len(dc)) // [userID]username
	for _, v := range dc {
		c := convertCommentFromDecred(v)

		// Fill in author info
		userID, ok := b.userPubkeys[c.PublicKey]
		if !ok {
			log.Errorf("getPropComments: userID lookup failed "+
				"pubkey:%v token:%v comment:%v", c.PublicKey,
				c.Token, c.CommentID)
		}
		u, ok := usernames[userID]
		if !ok && userID != "" {
			u = b.getUsernameById(userID)
			usernames[userID] = u
		}
		c.UserID = userID
		c.Username = u

		// Fill in result votes
		score, ok := b.commentScores[c.Token+c.CommentID]
		if !ok {
			log.Errorf("getPropComments: comment score lookup failed"+
				"pubkey:%v token:%v comment:%v", c.PublicKey, c.Token,
				c.CommentID)
		}
		c.ResultVotes = score

		comments = append(comments, c)
	}

	return comments, nil
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal, user *database.User) (*www.NewProposalReply, error) {
	log.Tracef("ProcessNewProposal")

	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	if !b.UserHasProposalCredits(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	err := b.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	// Assemble metadata record
	name, err := getProposalName(np.Files)
	if err != nil {
		return nil, err
	}
	md, err := encodeBackendProposalMetadata(BackendProposalMetadata{
		Version:   BackendProposalMetadataVersion,
		Timestamp: time.Now().Unix(),
		Name:      name,
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	})
	if err != nil {
		return nil, err
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{{
			ID:      mdStreamGeneral,
			Payload: string(md),
		}},
		Files: convertPropFilesFromWWW(np.Files),
	}

	// Handle test case
	if b.test {
		tokenBytes, err := util.Random(pd.TokenSize)
		if err != nil {
			return nil, err
		}

		testReply := pd.NewRecordReply{
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		return &www.NewProposalReply{
			CensorshipRecord: convertPropCensorFromPD(testReply.CensorshipRecord),
		}, nil
	}

	// Send politeiad request
	responseBody, err := b.makeRequest(http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted proposal name: %v", name)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewProposalReply: %v", err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Deduct proposal credit from user account
	err = b.SpendProposalCredit(user, cr.Token)
	if err != nil {
		return nil, err
	}

	// Fire off new proposal event
	b.fireEvent(EventTypeProposalSubmitted,
		EventDataProposalSubmitted{
			CensorshipRecord: &cr,
			ProposalName:     name,
			User:             user,
		},
	)

	return &www.NewProposalReply{
		CensorshipRecord: cr,
	}, nil
}

// ProcessProposalDetails fetches a specific proposal version from the records
// cache and returns it.
func (b *backend) ProcessProposalDetails(propDetails www.ProposalsDetails, user *database.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("ProcessProposalDetails")

	// Version is an optional query param. Fetch latest version
	// when query param is not specified.
	var prop *www.ProposalRecord
	var err error
	if propDetails.Version == "" {
		prop, err = b.getProp(propDetails.Token)
	} else {
		prop, err = b.getPropVersion(propDetails.Token, propDetails.Version)
	}
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Setup reply
	reply := www.ProposalDetailsReply{
		Proposal: *prop,
	}

	// Vetted proposals are viewable by everyone. The contents of
	// an unvetted proposal is only viewable by admins and the
	// proposal author. Unvetted proposal metadata is viewable by
	// everyone.
	if prop.State == www.PropStateUnvetted {
		var isAuthor bool
		var isAdmin bool
		// This is a public route so a user may not exist
		if user != nil {
			isAdmin = user.Admin
			isAuthor = (prop.UserId == user.ID.String())
		}

		// Strip the non-public proposal contents if user is
		// not the author or an admin
		if !isAuthor && !isAdmin {
			reply.Proposal.Name = ""
			reply.Proposal.Files = make([]www.File, 0)
		}
	}

	return &reply, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus, user *database.User) (*www.SetProposalStatusReply, error) {
	log.Tracef("ProcessSetProposalStatus %v", sps.Token)

	err := checkPublicKeyAndSignature(user, sps.PublicKey, sps.Signature,
		sps.Token, strconv.FormatUint(uint64(sps.ProposalStatus), 10),
		sps.StatusChangeMessage)
	if err != nil {
		return nil, err
	}

	// Ensure the status change message is not blank if the proposal
	// is being censored or abandoned
	if sps.StatusChangeMessage == "" &&
		(sps.ProposalStatus == www.PropStatusCensored ||
			sps.ProposalStatus == www.PropStatusAbandoned) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
		}
	}

	// Ensure user is an admin. Only admins are allowed to change
	// a proposal status.
	adminPubKey, ok := database.ActiveIdentityString(user.Identities)
	if !ok {
		return nil, fmt.Errorf("invalid admin identity: %v", user.ID)
	}

	// Handle test case
	if b.test {
		var reply www.SetProposalStatusReply
		reply.Proposal.Status = sps.ProposalStatus
		return &reply, nil
	}

	// Get proposal from cache
	pr, err := b.getProp(sps.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// The only time admins are allowed to change the status of
	// their own proposals is on testnet
	if !b.cfg.TestNet {
		authorID, ok := b.getUserIDByPubKey(pr.PublicKey)
		if !ok {
			return nil, fmt.Errorf("user not found for public key %v for "+
				"proposal %v", pr.PublicKey, pr.CensorshipRecord.Token)
		}

		if authorID == user.ID.String() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusReviewerAdminEqualsAuthor,
			}
		}
	}

	// Create change record
	newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
	blob, err := json.Marshal(MDStreamChanges{
		Version:             VersionMDStreamChanges,
		Timestamp:           time.Now().Unix(),
		NewStatus:           newStatus,
		AdminPubKey:         adminPubKey,
		StatusChangeMessage: sps.StatusChangeMessage,
	})
	if err != nil {
		return nil, err
	}

	// Create challenge
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	var challengeResponse string
	switch {
	case pr.State == www.PropStateUnvetted:
		// Unvetted status change

		// Verify status transition is valid
		switch {
		case pr.Status == www.PropStatusNotReviewed &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic):
		// allowed; continue
		case pr.Status == www.PropStatusUnreviewedChanges &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic):
			// allowed; continue
		default:
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}
		}

		// Setup request
		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdStreamChanges,
					Payload: string(blob),
				},
			},
		}

		// Send unvetted status change request
		responseBody, err := b.makeRequest(http.MethodPost,
			pd.SetUnvettedStatusRoute, sus)
		if err != nil {
			return nil, err
		}

		var susr pd.SetUnvettedStatusReply
		err = json.Unmarshal(responseBody, &susr)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"SetUnvettedStatusReply: %v", err)
		}
		challengeResponse = susr.Response

	case pr.State == www.PropStateVetted:
		// Vetted status change

		// We only allow a transition from public to abandoned
		if pr.Status != www.PropStatusPublic ||
			sps.ProposalStatus != www.PropStatusAbandoned {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}
		}

		// Ensure voting has not been started or authorized yet
		vdr, err := b.decredVoteDetails(pr.CensorshipRecord.Token)
		if err != nil {
			return nil, fmt.Errorf("decredVoteDetails: %v", err)
		}
		vd := convertVoteDetailsReplyFromDecred(*vdr)
		if vd.StartVoteReply.StartBlockHeight != "" ||
			voteIsAuthorized(vd.AuthorizeVoteReply) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}
		}

		// Setup request
		svs := pd.SetVettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdStreamChanges,
					Payload: string(blob),
				},
			},
		}

		// Send vetted status change request
		responseBody, err := b.makeRequest(http.MethodPost,
			pd.SetVettedStatusRoute, svs)
		if err != nil {
			return nil, err
		}

		var svsr pd.SetVettedStatusReply
		err = json.Unmarshal(responseBody, &svsr)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"SetVettedStatusReply: %v", err)
		}
		challengeResponse = svsr.Response

	default:
		return nil, fmt.Errorf("invalid proposal state %v: %v",
			pr.State, pr.CensorshipRecord.Token)
	}

	// Verify the challenge
	err = util.VerifyChallenge(b.cfg.Identity, challenge,
		challengeResponse)
	if err != nil {
		return nil, err
	}

	// Get record from the cache
	updatedProp, err := b.getPropVersion(pr.CensorshipRecord.Token, pr.Version)
	if err != nil {
		return nil, err
	}

	// Fire off proposal status change event
	b.eventManager._fireEvent(EventTypeProposalStatusChange,
		EventDataProposalStatusChange{
			Proposal:          updatedProp,
			AdminUser:         user,
			SetProposalStatus: &sps,
		},
	)

	return &www.SetProposalStatusReply{
		Proposal: *updatedProp,
	}, nil
}

// ProcessEditProposal attempts to edit a proposal on politeiad.
func (b *backend) ProcessEditProposal(ep www.EditProposal, user *database.User) (*www.EditProposalReply, error) {
	log.Tracef("ProcessEditProposal %v", ep.Token)

	// Validate proposal status
	cachedProp, err := b.getProp(ep.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if cachedProp.Status == www.PropStatusCensored ||
		cachedProp.Status == www.PropStatusAbandoned {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Ensure user is the proposal author
	if cachedProp.UserId != user.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotAuthor,
		}
	}

	// Validate proposal vote status
	vdr, err := b.decredVoteDetails(ep.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	bb, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	s := getVoteStatus(vd.AuthorizeVoteReply, vd.StartVoteReply, bb)
	if s != www.PropVoteStatusNotAuthorized {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Validate proposal. Convert it to www.NewProposal so that
	// we can reuse the function validateProposal.
	np := www.NewProposal{
		Files:     ep.Files,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	err = b.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	// Assemble metadata record
	name, err := getProposalName(ep.Files)
	if err != nil {
		return nil, err
	}

	backendMetadata := BackendProposalMetadata{
		Version:   BackendProposalMetadataVersion,
		Timestamp: time.Now().Unix(),
		Name:      name,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	md, err := encodeBackendProposalMetadata(backendMetadata)
	if err != nil {
		return nil, err
	}

	mds := []pd.MetadataStream{{
		ID:      mdStreamGeneral,
		Payload: string(md),
	}}

	// Check if any files need to be deleted
	var delFiles []string
	for _, v := range cachedProp.Files {
		found := false
		for _, c := range ep.Files {
			if v.Name == c.Name {
				found = true
			}
		}
		if !found {
			delFiles = append(delFiles, v.Name)
		}
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	e := pd.UpdateRecord{
		Token:       ep.Token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mds,
		FilesAdd:    convertPropFilesFromWWW(ep.Files),
		FilesDel:    delFiles,
	}

	var pdRoute string
	switch cachedProp.Status {
	case www.PropStatusNotReviewed, www.PropStatusUnreviewedChanges:
		pdRoute = pd.UpdateUnvettedRoute
	case www.PropStatusPublic:
		pdRoute = pd.UpdateVettedRoute
	default:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Send politeiad request
	responseBody, err := b.makeRequest(http.MethodPost, pdRoute, e)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pdReply pd.UpdateRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal UpdateUnvettedReply: %v", err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	updatedProp, err := b.getProp(ep.Token)
	if err != nil {
		return nil, err
	}

	// Fire off edit proposal event
	b.eventManager._fireEvent(EventTypeProposalEdited,
		EventDataProposalEdited{
			Proposal: updatedProp,
		},
	)

	return &www.EditProposalReply{
		Proposal: *updatedProp,
	}, nil
}

// ProcessAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (b *backend) ProcessAllVetted(v www.GetAllVetted) (*www.GetAllVettedReply, error) {
	log.Tracef("ProcessAllVetted")

	// Fetch all proposals from the cache
	all, err := b.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Filter for vetted proposals
	filter := proposalsFilter{
		After:  v.After,
		Before: v.Before,
		StateMap: map[www.PropStateT]bool{
			www.PropStateVetted: true,
		},
	}
	props := filterProps(filter, all)

	// Remove files from proposals
	for i, p := range props {
		p.Files = make([]www.File, 0)
		props[i] = p
	}

	return &www.GetAllVettedReply{
		Proposals: props,
	}, nil
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse
// order, because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted(u www.GetAllUnvetted) (*www.GetAllUnvettedReply, error) {
	log.Tracef("ProcessAllUnvetted")

	// Fetch all proposals from the cache
	all, err := b.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Filter for unvetted proposals
	filter := proposalsFilter{
		After:  u.After,
		Before: u.Before,
		StateMap: map[www.PropStateT]bool{
			www.PropStateUnvetted: true,
		},
	}
	props := filterProps(filter, all)

	// Remove files from proposals
	for i, p := range props {
		p.Files = make([]www.File, 0)
		props[i] = p
	}

	return &www.GetAllUnvettedReply{
		Proposals: props,
	}, nil
}

// ProcessProposalStats returns summary statistics on the number of proposals
// catagorized by proposal status.
func (b *backend) ProcessProposalsStats() (*www.ProposalsStatsReply, error) {
	inv, err := b.cache.InventoryStats()
	if err != nil {
		return nil, err
	}
	if inv.Invalid > 0 {
		// There should not be any invalid proposals so log an error
		// if any are found
		log.Errorf("ProcessProposalStats: %v invalid proposals found",
			inv.Invalid)
	}
	return &www.ProposalsStatsReply{
		NumOfCensored:        inv.Censored,
		NumOfUnvetted:        inv.NotReviewed,
		NumOfUnvettedChanges: inv.UnreviewedChanges,
		NumOfPublic:          inv.Public,
		NumOfAbandoned:       inv.Archived,
	}, nil
}

// ProcessCommentsGet returns all comments for a given proposal. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (b *backend) ProcessCommentsGet(token string, user *database.User) (*www.GetCommentsReply, error) {
	log.Tracef("ProcessCommentGet: %v", token)

	// Fetch proposal comments from cache
	c, err := b.getPropComments(token)
	if err != nil {
		return nil, err
	}

	// Get the last time the user accessed these comments. This is
	// a public route so a user may not exist.
	var accessTime int64
	if user != nil {
		if user.ProposalCommentsAccessTimes == nil {
			user.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		accessTime = user.ProposalCommentsAccessTimes[token]
		user.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = b.UserUpdate(*user)
		if err != nil {
			return nil, err
		}
	}

	return &www.GetCommentsReply{
		Comments:   c,
		AccessTime: accessTime,
	}, nil
}

func voteResults(sv www.StartVote, cv []www.CastVote) []www.VoteOptionResult {
	log.Tracef("voteResults: %v", sv.Vote.Token)

	// Tally votes
	votes := make(map[string]uint64)
	for _, v := range cv {
		votes[v.VoteBit]++
	}

	// Prepare vote option results
	results := make([]www.VoteOptionResult, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		results = append(results, www.VoteOptionResult{
			Option:        v,
			VotesReceived: votes[strconv.FormatUint(v.Bits, 10)],
		})
	}

	return results
}

func (b *backend) getVoteStatus(token string, bestBlock uint64) (*www.VoteStatusReply, error) {
	log.Tracef("getVoteStatus: %v", token)

	// Get vote details from cache
	vdr, err := b.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails %v: %v",
			token, err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)
	voteStatus := getVoteStatus(vd.AuthorizeVoteReply,
		vd.StartVoteReply, bestBlock)

	// Get cast votes from cache
	vrr, err := b.decredProposalVotes(token)
	if err != nil {
		return nil, fmt.Errorf("decredProposalVotes %v: %v",
			token, err)
	}
	sv, cv := convertVoteResultsReplyFromDecred(*vrr)

	return &www.VoteStatusReply{
		Token:              token,
		Status:             voteStatus,
		TotalVotes:         uint64(len(vrr.CastVotes)),
		OptionsResult:      voteResults(sv, cv),
		EndHeight:          vd.StartVoteReply.EndHeight,
		NumOfEligibleVotes: len(vd.StartVoteReply.EligibleTickets),
		QuorumPercentage:   vd.StartVote.Vote.QuorumPercentage,
		PassPercentage:     vd.StartVote.Vote.PassPercentage,
	}, nil
}

// ProcessVoteStatus returns the vote status for a given proposal
func (b *backend) ProcessVoteStatus(token string) (*www.VoteStatusReply, error) {
	log.Tracef("ProcessProposalVotingStatus: %v", token)

	// Ensure proposal is public
	pr, err := b.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Get best block
	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get vote status
	vs, err := b.getVoteStatus(token, bestBlock)
	if err != nil {
		return nil, fmt.Errorf("getVoteStatus: %v", err)
	}

	return vs, nil
}

// ProcessGetAllVoteStatus returns the vote status of all public proposals.
func (b *backend) ProcessGetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	log.Tracef("ProcessGetAllVoteStatus")

	// We need to determine best block height here in order
	// to set the voting status
	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get all proposals from cache
	all, err := b.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile votes statuses
	vrr := make([]www.VoteStatusReply, 0, len(all))
	for _, v := range all {
		// We only need public proposals
		if v.Status != www.PropStatusPublic {
			continue
		}

		// Get vote status for proposal
		vs, err := b.getVoteStatus(v.CensorshipRecord.Token, bestBlock)
		if err != nil {
			return nil, fmt.Errorf("getVoteStatus: %v", err)
		}

		vrr = append(vrr, *vs)
	}

	return &www.GetAllVoteStatusReply{
		VotesStatus: vrr,
	}, nil
}

func (b *backend) ProcessActiveVote() (*www.ActiveVoteReply, error) {
	log.Tracef("ProcessActiveVote")

	// We need to determine best block height here and only
	// return active votes.
	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Get all proposals from cache
	all, err := b.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile proposal vote tuples
	pvt := make([]www.ProposalVoteTuple, 0, len(all))
	for _, v := range all {
		// Get vote details from cache
		vdr, err := b.decredVoteDetails(v.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("ProcessActiveVote: decredVoteDetails failed %v: %v",
				v.CensorshipRecord.Token, err)
			continue
		}
		vd := convertVoteDetailsReplyFromDecred(*vdr)

		// We only want proposals that are currently being voted on
		s := getVoteStatus(vd.AuthorizeVoteReply, vd.StartVoteReply, bestBlock)
		if s != www.PropVoteStatusStarted {
			continue
		}

		pvt = append(pvt, www.ProposalVoteTuple{
			Proposal:       v,
			StartVote:      vd.StartVote,
			StartVoteReply: vd.StartVoteReply,
		})
	}

	return &www.ActiveVoteReply{
		Votes: pvt,
	}, nil
}

// ProcessVoteResults returns the vote details for a specific proposal and all
// of the votes that have been cast.
func (b *backend) ProcessVoteResults(token string) (*www.VoteResultsReply, error) {
	log.Tracef("ProcessVoteResults: %v", token)

	// Ensure proposal is public
	pr, err := b.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Get vote details from cache
	vdr, err := b.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}

	// Get cast votes from cache
	vrr, err := b.decredProposalVotes(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}

	return &www.VoteResultsReply{
		StartVote:      convertStartVoteFromDecred(vdr.StartVote),
		StartVoteReply: convertStartVoteReplyFromDecred(vdr.StartVoteReply),
		CastVotes:      convertCastVotesFromDecred(vrr.CastVotes),
	}, nil
}
