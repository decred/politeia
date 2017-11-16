package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

const BackendProposalMetadataVersion = 1

type BackendProposalMetadata struct {
	Version   uint64 `json:"version"`   // BackendProposalMetadata version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
}

// encodeBackendProposalMetadata encodes BackendProposalMetadata into a JSON
// byte slice.
func encodeBackendProposalMetadata(md BackendProposalMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendProposalMetadata decodes a JSON byte slice into a
// BackendProposalMetadata.
func decodeBackendProposalMetadata(payload []byte) (*BackendProposalMetadata, error) {
	var md BackendProposalMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// ProcessAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (b *backend) ProcessAllVetted(v www.GetAllVetted) *www.GetAllVettedReply {
	proposals := b.getProposals(v.After, v.Before, map[www.PropStatusT]bool{
		www.PropStatusPublic: true,
	})

	b.RLock()
	defer b.RUnlock()

	for i, proposal := range proposals {
		count := uint(len(b.comments[proposal.CensorshipRecord.Token]))
		proposals[i].NumComments = &count
	}

	return &www.GetAllVettedReply{
		Proposals: proposals,
	}
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted(u www.GetAllUnvetted) *www.GetAllUnvettedReply {
	return &www.GetAllUnvettedReply{
		Proposals: b.getProposals(u.After, u.Before,
			map[www.PropStatusT]bool{
				www.PropStatusNotReviewed: true,
				www.PropStatusCensored:    true,
			}),
	}
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal, user *database.User) (*www.NewProposalReply, error) {
	log.Tracef("ProcessNewProposal")

	err := b.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	var reply www.NewProposalReply
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	name, err := getProposalName(np.Files)
	if err != nil {
		return nil, err
	}

	// Assemble metdata record
	ts := time.Now().Unix()
	md, err := encodeBackendProposalMetadata(BackendProposalMetadata{
		Version:   BackendProposalMetadataVersion,
		Timestamp: ts,
		Name:      name,
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	})
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

	var pdReply pd.NewRecordReply
	if b.test {
		tokenBytes, err := util.Random(16)
		if err != nil {
			return nil, err
		}

		pdReply.CensorshipRecord = pd.CensorshipRecord{
			Token: hex.EncodeToString(tokenBytes),
		}

		// Add the new proposal to the cache.
		b.Lock()
		b.inventory = append(b.inventory, www.ProposalRecord{
			Name:             name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        ts,
			PublicKey:        np.PublicKey,
			Signature:        np.Signature,
			Files:            np.Files,
			CensorshipRecord: convertPropCensorFromPD(pdReply.CensorshipRecord),
		})
		b.inventoryVersion++
		b.initComment(pdReply.CensorshipRecord.Token)
		b.Unlock()
	} else {
		responseBody, err := b.makeRequest(http.MethodPost,
			pd.NewRecordRoute, n)
		if err != nil {
			return nil, err
		}

		log.Infof("Submitted proposal name: %v", name)
		for k, f := range n.Files {
			log.Infof("%02v: %v %v", k, f.Name, f.Digest)
		}

		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal NewProposalReply: %v",
				err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
		if err != nil {
			return nil, err
		}

		// Add the new proposal to the cache.
		r := www.ProposalRecord{
			Name:             name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        ts,
			PublicKey:        np.PublicKey,
			Signature:        np.Signature,
			Files:            make([]www.File, 0),
			CensorshipRecord: convertPropCensorFromPD(pdReply.CensorshipRecord),
		}
		b.Lock()
		b.inventory = append(b.inventory, r)
		b.inventoryVersion++
		b.initComment(pdReply.CensorshipRecord.Token)
		b.Unlock()
	}

	reply.CensorshipRecord = convertPropCensorFromPD(pdReply.CensorshipRecord)
	return &reply, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal
// from unreviewed to either published or censored.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus, user *database.User) (*www.SetProposalStatusReply, error) {
	// Validate signature
	err := checkSig(user, sps.Signature, sps.Token,
		strconv.FormatUint(uint64(sps.ProposalStatus), 10))
	if err != nil {
		return nil, err
	}

	var reply www.SetProposalStatusReply
	var pdReply pd.SetUnvettedStatusReply
	if b.test {
		pdReply.Status = convertPropStatusFromWWW(sps.ProposalStatus)
	} else {
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		// Create chnage record
		newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
		r := MDStreamChanges{
			Timestamp: time.Now().Unix(),
			NewStatus: newStatus,
		}
		if ai, ok := database.ActiveIdentityString(user.Identities); !ok {
			return nil, fmt.Errorf("invalid admin identity: %v",
				user.ID)
		} else {
			r.AdminPubKey = ai
		}
		blob, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}

		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDOverwrite: []pd.MetadataStream{
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

		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v",
				err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
		if err != nil {
			return nil, err
		}
	}

	// Update the cached proposal with the new status and return the reply.
	b.Lock()
	defer b.Unlock()
	for k, v := range b.inventory {
		if v.CensorshipRecord.Token == sps.Token {
			s := convertPropStatusFromPD(pdReply.Status)
			b.inventory[k].Status = s
			reply.ProposalStatus = s
			return &reply, nil
		}
	}

	return nil, www.UserError{
		ErrorCode: www.ErrorStatusProposalNotFound,
	}
}

// ProcessProposalDetails tries to fetch the full details of a proposal from politeiad.
func (b *backend) ProcessProposalDetails(propDetails www.ProposalsDetails, isUserAdmin bool) (*www.ProposalDetailsReply, error) {
	var reply www.ProposalDetailsReply
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	var cachedProposal *www.ProposalRecord
	b.RLock()
	for _, v := range b.inventory {
		if v.CensorshipRecord.Token == propDetails.Token {
			cachedProposal = &v
			break
		}
	}
	b.RUnlock()
	if cachedProposal == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	var isVettedProposal bool
	var requestObject interface{}
	if cachedProposal.Status == www.PropStatusPublic {
		isVettedProposal = true
		requestObject = pd.GetVetted{
			Token:     propDetails.Token,
			Challenge: hex.EncodeToString(challenge),
		}
	} else {
		isVettedProposal = false
		requestObject = pd.GetUnvetted{
			Token:     propDetails.Token,
			Challenge: hex.EncodeToString(challenge),
		}
	}

	if b.test {
		reply.Proposal = *cachedProposal
		return &reply, nil
	}

	// The title and files for unvetted proposals should not be viewable by
	// non-admins; only the proposal meta data (status, censorship data, etc)
	// should be publicly viewable.
	if !isVettedProposal && !isUserAdmin {
		reply.Proposal = www.ProposalRecord{
			Status:           cachedProposal.Status,
			Timestamp:        cachedProposal.Timestamp,
			PublicKey:        cachedProposal.PublicKey,
			Signature:        cachedProposal.Signature,
			CensorshipRecord: cachedProposal.CensorshipRecord,
		}
		return &reply, nil
	}

	var route string
	if isVettedProposal {
		route = pd.GetVettedRoute
	} else {
		route = pd.GetUnvettedRoute
	}

	responseBody, err := b.makeRequest(http.MethodPost, route, requestObject)
	if err != nil {
		return nil, err
	}

	var response string
	var proposal pd.Record
	if isVettedProposal {
		var pdReply pd.GetVettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetVettedReply: %v", err)
		}

		response = pdReply.Response
		proposal = pdReply.Record
	} else {
		var pdReply pd.GetUnvettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetUnvettedReply: %v", err)
		}

		response = pdReply.Response
		proposal = pdReply.Record
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge, response)
	if err != nil {
		return nil, err
	}

	reply.Proposal = convertPropFromPD(proposal)
	return &reply, nil
}

// getProposalName returns the proposal name based on the index markdown file.
func getProposalName(files []www.File) (string, error) {
	for _, file := range files {
		if file.Name == indexFile {
			return util.GetProposalName(file.Payload)
		}
	}
	return "", nil
}

func (b *backend) getProposals(after, before string, statusMap map[www.PropStatusT]bool) []www.ProposalRecord {
	b.RLock()
	defer b.RUnlock()

	// pageStarted stores whether or not it's okay to start adding
	// proposals to the array. If the after or before parameter is
	// supplied, we must find the beginning (or end) of the page first.
	pageStarted := (after == "" && before == "")
	beforeIdx := -1
	proposals := make([]www.ProposalRecord, 0)

	// Iterate in reverse order because they're sorted by oldest timestamp
	// first.
	for i := len(b.inventory) - 1; i >= 0; i-- {
		proposal := b.inventory[i]
		if _, ok := statusMap[proposal.Status]; ok {
			if pageStarted {
				proposals = append(proposals, proposal)
				if len(proposals) >= www.ProposalListPageSize {
					break
				}
			} else if after != "" {
				// The beginning of the page has been found, so
				// the next public proposal is added.
				pageStarted = proposal.CensorshipRecord.Token == after
			} else if before != "" {
				// The end of the page has been found, so we'll
				// have to iterate in the other direction to
				// add the proposals; save the current index.
				if proposal.CensorshipRecord.Token == before {
					beforeIdx = i
					break
				}
			}
		}
	}

	// If beforeIdx is set, the caller is asking for vetted proposals whose
	// last result is before the provided proposal.
	if beforeIdx >= 0 {
		for _, proposal := range b.inventory[beforeIdx+1:] {
			if _, ok := statusMap[proposal.Status]; ok {
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
	}

	return proposals
}

func (b *backend) validateProposal(np www.NewProposal, user *database.User) error {
	log.Tracef("validateProposal")

	// Obtain signature
	sig, err := util.ConvertSignature(np.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify user used correct key
	id, ok := database.ActiveIdentity(user.Identities)
	if !ok {
		return www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if hex.EncodeToString(id[:]) != np.PublicKey {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-emtpy payload.
	if len(np.Files) == 0 || np.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(np.Files))
	// Check that the file number policy is followed.
	var (
		numMDs, numImages, numIndexFiles      int
		mdExceedsMaxSize, imageExceedsMaxSize bool
		hashes                                []*[sha256.Size]byte
	)
	for _, v := range np.Files {
		filenames[v.Name]++
		var (
			data []byte
			err  error
		)
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numMDs++

			if v.Name == indexFile {
				numIndexFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxMDSize {
				mdExceedsMaxSize = true
			}
		}

		// Append digest to array for merkle root calculation
		digest := util.Digest(data)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	// verify duplicate file names
	if len(np.Files) > 1 {
		var repeated []string
		for name, count := range filenames {
			if count > 1 {
				repeated = append(repeated, name)
			}
		}
		if len(repeated) > 0 {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: repeated,
			}
		}
	}

	// we expect one index file
	if numIndexFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{indexFile},
		}
	}

	if numMDs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if mdExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
	}

	if imageExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
		}
	}

	// proposal title validation
	name, err := getProposalName(np.Files)
	if err != nil {
		return err
	}
	if !util.IsValidProposalName(name) {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalInvalidTitle,
			ErrorContext: []string{util.CreateProposalTitleRegex()},
		}
	}

	// Note that we need validate the string representation of the merkle
	mr := merkle.Root(hashes)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}
