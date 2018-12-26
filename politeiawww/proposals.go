package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

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
	var pdReply pd.NewRecordReply
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

	// XXX this is here temporarily until decredplugin data has
	// been added to the caching layer
	b.newInventoryRecord(pd.Record{
		Status:    0,
		Timestamp: 0,
		CensorshipRecord: pd.CensorshipRecord{
			Token: cr.Token,
		},
		Metadata: make([]pd.MetadataStream, 0),
		Version:  "1",
	})
	if err != nil {
		log.Errorf("ProcessNewProposal could not add record into"+
			"inventory: %v", err)
	}

	return &www.NewProposalReply{
		CensorshipRecord: cr,
	}, nil
}

// ProcessProposalDetails fetches a specific proposal version from the records
// cache and returns it.
func (b *backend) ProcessProposalDetails(propDetails www.ProposalsDetails, user *database.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("ProcessProposalDetails")

	// Version is an optional query param. Fetch latest version when
	// query param is not specified.
	var record *cache.Record
	var err error
	if propDetails.Version == "" {
		record, err = b.cache.RecordGetLatest(propDetails.Token)
	} else {
		record, err = b.cache.RecordGet(propDetails.Token, propDetails.Version)
	}
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Fill in proposal author info
	prop := convertPropFromCache(*record)
	userID, ok := b.getUserIDByPubKey(prop.PublicKey)
	if !ok {
		// Complain but don't return since proposal details can still
		// be returned
		log.Errorf("ProcessProposalDetails: user not found for "+
			"public key %v, for proposal %v", prop.PublicKey,
			prop.CensorshipRecord.Token)
	}
	prop.UserId = userID
	prop.Username = b.getUsernameById(userID)

	// Setup reply
	reply := www.ProposalDetailsReply{
		Proposal: prop,
	}

	// Vetted proposals are viewable by everyone. The contents of
	// an unvetted proposal is only viewable by admins and the
	// proposal author. Unvetted proposal metadata is viewable by
	// everyone.
	switch prop.State {
	case www.PropStateVetted:
		// TODO: Get NumComments

	case www.PropStateUnvetted:
		var isAuthor bool
		var isAdmin bool
		// This is a public route so a user may not exist
		if user != nil {
			isAdmin = user.Admin
			isAuthor = (prop.UserId == user.ID.String())
		}

		// Strip proposal contents if user is not author or an admin
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
	r, err := b.cache.RecordGetLatest(sps.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// The only time admins are allowed to change the status of
	// their own proposals is on testnet
	if !b.cfg.TestNet {
		authorID, ok := b.getUserIDByPubKey(pr.PublicKey)
		if !ok {
			return nil, fmt.Errorf("user not found for public key %v "+
				"for proposal %v", pr.PublicKey, pr.CensorshipRecord.Token)
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
		if pr.Status == www.PropStatusNotReviewed &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic) {
			// allowed; continue
		} else if pr.Status == www.PropStatusUnreviewedChanges &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic) {
			// allowed; continue
		} else {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}
		}

		// Send unvetted status change request
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

		// XXX we need this until decredplugin data has been added to
		// the cache
		ir, err := b.getInventoryRecord(pr.CensorshipRecord.Token)
		if err != nil {
			return nil, err
		}

		// Ensure voting has not been started or authorized yet
		if ir.voting.StartBlockHeight != "" || voteIsAuthorized(ir) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}
		}

		// Send vetted status change request
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

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge,
		challengeResponse)
	if err != nil {
		return nil, err
	}

	// Get record from cache
	r, err = b.cache.RecordGet(pr.CensorshipRecord.Token, pr.Version)
	if err != nil {
		return nil, err
	}
	updatedProp := convertPropFromCache(*r)

	// Fire off proposal status change event
	b.eventManager._fireEvent(EventTypeProposalStatusChange,
		EventDataProposalStatusChange{
			Proposal:          &updatedProp,
			AdminUser:         user,
			SetProposalStatus: &sps,
		},
	)

	return &www.SetProposalStatusReply{
		Proposal: updatedProp,
	}, nil
}

// ProcessEditProposal attempts to edit a proposal on politeiad.
func (b *backend) ProcessEditProposal(user *database.User, ep www.EditProposal) (*www.EditProposalReply, error) {
	log.Tracef("ProcessEditProposal %v", ep.Token)

	// Get proposal from cache
	r, err := b.cache.RecordGetLatest(ep.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	cachedProp := convertPropFromCache(*r)

	// Ensure user is the proposal author
	authorID, ok := b.getUserIDByPubKey(cachedProp.PublicKey)
	if !ok {
		return nil, fmt.Errorf("user not found for pubkey %v for proposal %v",
			cachedProp.PublicKey, cachedProp.CensorshipRecord.Token)
	}
	if authorID != user.ID.String() {
		log.Debugf("ProcessEditProposal: userID %v does not match authorID %v",
			user.ID.String(), authorID)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotAuthor,
		}
	}

	// it is ok to race invRecord.
	// In theory the user can not issue racing edit prop commands. In
	// practice a network hickup can submit the same edit twice but then
	// the decred plugin should reject the second call as "no changes".
	// A malicious user that alters the code to issue concurrent updates
	// could result in an out-of-order cache update.
	// Politeaid will remain coherent.

	// XXX remove this once vote data has been added to cache
	b.RLock()
	invRecord, err := b._getInventoryRecord(ep.Token)
	b.RUnlock()
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Validate proposal vote status
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	if getVoteStatus(invRecord, bb) != www.PropVoteStatusNotAuthorized {
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
	// TODO: don't use inventory record here
	var delFiles []string
	for _, v := range invRecord.record.Files {
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
	if cachedProp.Status == www.PropStatusNotReviewed ||
		cachedProp.Status == www.PropStatusUnreviewedChanges {
		pdRoute = pd.UpdateUnvettedRoute
	} else if cachedProp.Status == www.PropStatusPublic {
		pdRoute = pd.UpdateVettedRoute
	} else {
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

	// Delete vote authorization if one existed before the edit
	if invRecord.voteAuthorization.Receipt != "" {
		err = b.setRecordVoteAuthorization(ep.Token, www.AuthorizeVoteReply{})
		if err != nil {
			// This should be impossible and we can't fail here
			log.Criticalf("ProcessEditProposal: could not delete vote"+
				"authorization: %v", err)
		}
	}

	// Get proposal from the cache
	r, err = b.cache.RecordGetLatest(ep.Token)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Fire off edit proposal event
	b.eventManager._fireEvent(EventTypeProposalEdited,
		EventDataProposalEdited{
			Proposal: &pr,
		},
	)

	return &www.EditProposalReply{
		Proposal: pr,
	}, nil
}
