// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// indexFile contains the file name of the index file
	indexFile = "index.md"

	// mdStream* indicate the metadata stream used for various types
	mdStreamGeneral = 0 // General information for this proposal
	mdStreamChanges = 2 // Changes to record
	// Note that 14 is in use by the decred plugin
	// Note that 15 is in use by the decred plugin

	VersionMDStreamChanges         = 1
	BackendProposalMetadataVersion = 1
)

type MDStreamChanges struct {
	Version             uint             `json:"version"`                       // Version of the struct
	AdminPubKey         string           `json:"adminpubkey"`                   // Identity of the administrator
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // NewStatus
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Status change message
	Timestamp           int64            `json:"timestamp"`                     // Timestamp of the change
}

type BackendProposalMetadata struct {
	Version   uint64 `json:"version"`   // BackendProposalMetadata version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
}

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

type VoteDetails struct {
	AuthorizeVote      www.AuthorizeVote      // Authorize vote
	AuthorizeVoteReply www.AuthorizeVoteReply // Authorize vote reply
	StartVote          www.StartVote          // Start vote
	StartVoteReply     www.StartVoteReply     // Start vote reply
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

// decodeMDStreamChanges decodes a JSON byte slice into a slice of
// MDStreamChanges.
func decodeMDStreamChanges(payload []byte) ([]MDStreamChanges, error) {
	var msc []MDStreamChanges

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m MDStreamChanges
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		msc = append(msc, m)
	}

	return msc, nil
}

// validateVoteBit ensures that bit is a valid vote bit.
func validateVoteBit(vote www.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}

// validateProposal ensures that a submitted proposal hashes, merkle and
// signarures are valid.
func validateProposal(np www.NewProposal, u *user.User) error {
	log.Tracef("validateProposal")

	// Obtain signature
	sig, err := util.ConvertSignature(np.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(u, np.PublicKey)
	if err != nil {
		return err
	}

	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(np.Files) == 0 || np.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(np.Files))
	// Check that the file number policy is followed.
	var (
		numMDs, numImages, numIndexFiles      uint
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
			ErrorContext: []string{util.CreateProposalNameRegex()},
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

// voteIsAuthorized returns whether the author of the proposal has authorized
// an admin to start the voting period for the proposal.
func voteIsAuthorized(avr www.AuthorizeVoteReply) bool {
	if avr.Receipt == "" {
		// Vote has not been authorized yet
		return false
	} else if avr.Action == www.AuthVoteActionRevoke {
		// Vote authorization was revoked
		return false
	}
	return true
}

// getVoteStatus returns the status for the provided vote.
func getVoteStatus(avr www.AuthorizeVoteReply, svr www.StartVoteReply, bestBlock uint64) www.PropVoteStatusT {
	if svr.StartBlockHeight == "" {
		// Vote has not started. Check if it's been authorized yet.
		if voteIsAuthorized(avr) {
			return www.PropVoteStatusAuthorized
		} else {
			return www.PropVoteStatusNotAuthorized
		}
	}

	// Vote has at least been started. Check if it has finished.
	ee, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		// This should not happen
		log.Errorf("getVoteStatus: ParseUint failed on '%v': %v",
			svr.EndHeight, err)
		return www.PropVoteStatusInvalid
	}

	if bestBlock >= ee {
		return www.PropVoteStatusFinished
	}
	return www.PropVoteStatusStarted
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

// convertWWWPropCreditFromDatabasePropCredit coverts a database proposal
// credit to a v1 proposal credit.
func convertWWWPropCreditFromDatabasePropCredit(credit user.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}

// getProp gets the most recent verions of the given proposal from the cache
// then fills in any missing fields before returning the proposal.
func (p *politeiawww) getProp(token string) (*www.ProposalRecord, error) {
	log.Tracef("getProp: %v", token)

	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Find the number of comments for the proposal
	dc, err := p.decredGetComments(token)
	if err != nil {
		log.Errorf("getProp: decredGetComments failed "+
			"for token %v", token)
	}
	pr.NumComments = uint(len(dc))

	p.RLock()
	defer p.RUnlock()

	// Fill in proposal author info
	userID, ok := p.userPubkeys[pr.PublicKey]
	if !ok {
		log.Errorf("getProp: userID lookup failed for "+
			"token:%v pubkey:%v", token, pr.PublicKey)
	}
	pr.UserId = userID
	pr.Username = p.getUsernameById(userID)

	return &pr, nil
}

// getPropVersion gets a specific version of a proposal from the cache then
// fills in any misssing fields before returning the proposal.
func (p *politeiawww) getPropVersion(token, version string) (*www.ProposalRecord, error) {
	log.Tracef("getPropVersion: %v %v", token, version)

	r, err := p.cache.RecordVersion(token, version)
	if err != nil {
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Fetch number of comments for proposal from cache
	dc, err := p.decredGetComments(token)
	if err != nil {
		log.Errorf("getPropVersion: decredGetComments "+
			"failed for token %v", token)
	}
	pr.NumComments = uint(len(dc))

	p.RLock()
	defer p.RUnlock()

	// Fill in proposal author info
	userID, ok := p.userPubkeys[pr.PublicKey]
	if !ok {
		log.Errorf("getPropVersion: user not found for "+
			"pubkey:%v token:%v", pr.PublicKey, token)
	}
	pr.UserId = userID
	pr.Username = p.getUsernameById(userID)

	return &pr, nil
}

// getAllProps gets the latest version of all proposals from the cache then
// fills any missing fields before returning the proposals.
func (p *politeiawww) getAllProps() ([]www.ProposalRecord, error) {
	log.Tracef("getAllProps")

	// Get proposals from cache
	records, err := p.cache.Inventory()
	if err != nil {
		return nil, err
	}

	// Fill in the number of comments for each proposal
	props := make([]www.ProposalRecord, 0, len(records))
	for _, v := range records {
		pr := convertPropFromCache(v)

		dc, err := p.decredGetComments(pr.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("getAllProps: decredGetComments failed "+
				"for token %v", pr.CensorshipRecord.Token)
		}
		pr.NumComments = uint(len(dc))

		props = append(props, pr)
	}

	p.RLock()
	defer p.RUnlock()

	// Fill in author info for each proposal. Cache usernames to
	// prevent duplicate database lookups.
	usernames := make(map[string]string, len(props)) // [userID]username
	for i, pr := range props {
		userID, ok := p.userPubkeys[pr.PublicKey]
		if !ok {
			log.Errorf("getAllProps: userID lookup failed for "+
				"token:%v pubkey:%v", pr.CensorshipRecord.Token,
				pr.PublicKey)
		}
		pr.UserId = userID

		u, ok := usernames[userID]
		if !ok {
			u = p.getUsernameById(userID)
			usernames[userID] = u
		}
		pr.Username = u

		props[i] = pr
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
func (p *politeiawww) getUserProps(filter proposalsFilter) ([]www.ProposalRecord, *proposalsSummary, error) {
	log.Tracef("getUserProps: %v", filter.UserID)

	if filter.UserID == "" {
		return nil, nil, fmt.Errorf("filter missing userID")
	}

	// Get the latest version of all proposals from the cache
	all, err := p.getAllProps()
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

func (p *politeiawww) getPropComments(token string) ([]www.Comment, error) {
	log.Tracef("getPropComments: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	p.RLock()
	defer p.RUnlock()

	// Fill in politeiawww data. Cache usernames to reduce
	// database lookups.
	comments := make([]www.Comment, 0, len(dc))
	usernames := make(map[string]string, len(dc)) // [userID]username
	for _, v := range dc {
		c := convertCommentFromDecred(v)

		// Fill in author info
		userID, ok := p.userPubkeys[c.PublicKey]
		if !ok {
			log.Errorf("getPropComments: userID lookup failed "+
				"pubkey:%v token:%v comment:%v", c.PublicKey,
				c.Token, c.CommentID)
		}
		u, ok := usernames[userID]
		if !ok && userID != "" {
			u = p.getUsernameById(userID)
			usernames[userID] = u
		}
		c.UserID = userID
		c.Username = u

		// Fill in result votes
		score, ok := p.commentScores[c.Token+c.CommentID]
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

// processNewProposal tries to submit a new proposal to politeiad.
func (p *politeiawww) processNewProposal(np www.NewProposal, user *user.User) (*www.NewProposalReply, error) {
	log.Tracef("processNewProposal")

	if !p.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	if !p.UserHasProposalCredits(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	err := validateProposal(np, user)
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
	if p.test {
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
	responseBody, err := p.makeRequest(http.MethodPost,
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

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Deduct proposal credit from user account
	err = p.SpendProposalCredit(user, cr.Token)
	if err != nil {
		return nil, err
	}

	// Fire off new proposal event
	p.fireEvent(EventTypeProposalSubmitted,
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

// processProposalDetails fetches a specific proposal version from the records
// cache and returns it.
func (p *politeiawww) processProposalDetails(propDetails www.ProposalsDetails, user *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails")

	// Version is an optional query param. Fetch latest version
	// when query param is not specified.
	var prop *www.ProposalRecord
	var err error
	if propDetails.Version == "" {
		prop, err = p.getProp(propDetails.Token)
	} else {
		prop, err = p.getPropVersion(propDetails.Token, propDetails.Version)
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

// processSetProposalStatus changes the status of an existing proposal.
func (p *politeiawww) processSetProposalStatus(sps www.SetProposalStatus, u *user.User) (*www.SetProposalStatusReply, error) {
	log.Tracef("processSetProposalStatus %v", sps.Token)

	err := checkPublicKeyAndSignature(u, sps.PublicKey, sps.Signature,
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

	// Handle test case
	if p.test {
		var reply www.SetProposalStatusReply
		reply.Proposal.Status = sps.ProposalStatus
		return &reply, nil
	}

	// Get proposal from cache
	pr, err := p.getProp(sps.Token)
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
	if !p.cfg.TestNet {
		authorID, ok := p.getUserIDByPubKey(pr.PublicKey)
		if !ok {
			return nil, fmt.Errorf("user not found for public key %v for "+
				"proposal %v", pr.PublicKey, pr.CensorshipRecord.Token)
		}

		if authorID == u.ID.String() {
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
		AdminPubKey:         u.PublicKey(),
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
		responseBody, err := p.makeRequest(http.MethodPost,
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
		vdr, err := p.decredVoteDetails(pr.CensorshipRecord.Token)
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
		responseBody, err := p.makeRequest(http.MethodPost,
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
	err = util.VerifyChallenge(p.cfg.Identity, challenge,
		challengeResponse)
	if err != nil {
		return nil, err
	}

	// Get record from the cache
	updatedProp, err := p.getPropVersion(pr.CensorshipRecord.Token, pr.Version)
	if err != nil {
		return nil, err
	}

	// Fire off proposal status change event
	p.fireEvent(EventTypeProposalStatusChange,
		EventDataProposalStatusChange{
			Proposal:          updatedProp,
			AdminUser:         u,
			SetProposalStatus: &sps,
		},
	)

	return &www.SetProposalStatusReply{
		Proposal: *updatedProp,
	}, nil
}

// processEditProposal attempts to edit a proposal on politeiad.
func (p *politeiawww) processEditProposal(ep www.EditProposal, u *user.User) (*www.EditProposalReply, error) {
	log.Tracef("processEditProposal %v", ep.Token)

	// Validate proposal status
	cachedProp, err := p.getProp(ep.Token)
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
	if cachedProp.UserId != u.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotAuthor,
		}
	}

	// Validate proposal vote status
	vdr, err := p.decredVoteDetails(ep.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	bb, err := p.getBestBlock()
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
	err = validateProposal(np, u)
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
	responseBody, err := p.makeRequest(http.MethodPost, pdRoute, e)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pdReply pd.UpdateRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal UpdateUnvettedReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	updatedProp, err := p.getProp(ep.Token)
	if err != nil {
		return nil, err
	}

	// Fire off edit proposal event
	p.fireEvent(EventTypeProposalEdited,
		EventDataProposalEdited{
			Proposal: updatedProp,
		},
	)

	return &www.EditProposalReply{
		Proposal: *updatedProp,
	}, nil
}

// processAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (p *politeiawww) processAllVetted(v www.GetAllVetted) (*www.GetAllVettedReply, error) {
	log.Tracef("processAllVetted")

	// Fetch all proposals from the cache
	all, err := p.getAllProps()
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

// processAllUnvetted returns an array of all unvetted proposals in reverse
// order, because they're sorted by oldest timestamp first.
func (p *politeiawww) processAllUnvetted(u www.GetAllUnvetted) (*www.GetAllUnvettedReply, error) {
	log.Tracef("processAllUnvetted")

	// Fetch all proposals from the cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("processAllUnvetted getAllProps: %v",
			err)
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
// categorized by proposal status.
func (p *politeiawww) processProposalsStats() (*www.ProposalsStatsReply, error) {
	inv, err := p.cache.InventoryStats()
	if err != nil {
		return nil, err
	}
	if inv.Invalid > 0 {
		// There should not be any invalid proposals so log an error
		// if any are found
		log.Errorf("processProposalsStats: %v invalid proposals found",
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

// processCommentsGet returns all comments for a given proposal. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processCommentsGet(token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("ProcessCommentGet: %v", token)

	// Fetch proposal comments from cache
	c, err := p.getPropComments(token)
	if err != nil {
		return nil, err
	}

	// Get the last time the user accessed these comments. This is
	// a public route so a user may not exist.
	var accessTime int64
	if u != nil {
		if u.ProposalCommentsAccessTimes == nil {
			u.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		accessTime = u.ProposalCommentsAccessTimes[token]
		u.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = p.db.UserUpdate(*u)
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

func (p *politeiawww) getVoteStatus(token string, bestBlock uint64) (*www.VoteStatusReply, error) {
	log.Tracef("getVoteStatus: %v", token)

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails %v: %v",
			token, err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)
	voteStatus := getVoteStatus(vd.AuthorizeVoteReply,
		vd.StartVoteReply, bestBlock)

	// Get cast votes from cache
	vrr, err := p.decredProposalVotes(token)
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

// processVoteStatus returns the vote status for a given proposal
func (p *politeiawww) processVoteStatus(token string) (*www.VoteStatusReply, error) {
	log.Tracef("ProcessProposalVotingStatus: %v", token)

	// Ensure proposal is public
	pr, err := p.getProp(token)
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
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get vote status
	vs, err := p.getVoteStatus(token, bestBlock)
	if err != nil {
		return nil, fmt.Errorf("getVoteStatus: %v", err)
	}

	return vs, nil
}

// processGetAllVoteStatus returns the vote status of all public proposals.
func (p *politeiawww) processGetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	log.Tracef("processGetAllVoteStatus")

	// We need to determine best block height here in order
	// to set the voting status
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Get all proposals from cache
	all, err := p.getAllProps()
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
		vs, err := p.getVoteStatus(v.CensorshipRecord.Token, bestBlock)
		if err != nil {
			return nil, fmt.Errorf("getVoteStatus: %v", err)
		}

		vrr = append(vrr, *vs)
	}

	return &www.GetAllVoteStatusReply{
		VotesStatus: vrr,
	}, nil
}

func (p *politeiawww) processActiveVote() (*www.ActiveVoteReply, error) {
	log.Tracef("processActiveVote")

	// We need to determine best block height here and only
	// return active votes.
	bestBlock, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Get all proposals from cache
	all, err := p.getAllProps()
	if err != nil {
		return nil, fmt.Errorf("getAllProps: %v", err)
	}

	// Compile proposal vote tuples
	pvt := make([]www.ProposalVoteTuple, 0, len(all))
	for _, v := range all {
		// Get vote details from cache
		vdr, err := p.decredVoteDetails(v.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("processActiveVote: decredVoteDetails failed %v: %v",
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

// processVoteResults returns the vote details for a specific proposal and all
// of the votes that have been cast.
func (p *politeiawww) processVoteResults(token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", token)

	// Ensure proposal is public
	pr, err := p.getProp(token)
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
	vdr, err := p.decredVoteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}

	// Get cast votes from cache
	vrr, err := p.decredProposalVotes(token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}

	return &www.VoteResultsReply{
		StartVote:      convertStartVoteFromDecred(vdr.StartVote),
		StartVoteReply: convertStartVoteReplyFromDecred(vdr.StartVoteReply),
		CastVotes:      convertCastVotesFromDecred(vrr.CastVotes),
	}, nil
}

// processCastVotes handles the www.Ballot call
func (p *politeiawww) processCastVotes(ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	payload, err := decredplugin.EncodeBallot(convertBallotFromWWW(*ballot))
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBallot,
		CommandID: decredplugin.CmdBallot,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	// Decode plugin reply
	br, err := decredplugin.DecodeBallotReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	brr := convertBallotReplyFromDecredPlugin(*br)
	return &brr, nil
}

// processProposalPaywallDetails returns a proposal paywall that enables the
// the user to purchase proposal credits. The user can only have one paywall
// active at a time.  If no paywall currently exists, a new one is created and
// the user is added to the paywall pool.
func (p *politeiawww) processProposalPaywallDetails(u *user.User) (*www.ProposalPaywallDetailsReply, error) {
	log.Tracef("processProposalPaywallDetails")

	// Ensure paywall is enabled
	if !p.paywallIsEnabled() {
		return &www.ProposalPaywallDetailsReply{}, nil
	}

	// Proposal paywalls cannot be generated until the user has paid their
	// user registration fee.
	if !p.HasUserPaid(u) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	var pp *user.ProposalPaywall
	if p.userHasValidProposalPaywall(u) {
		// Don't create a new paywall if a valid one already exists.
		pp = p.mostRecentProposalPaywall(u)
	} else {
		// Create a new paywall.
		var err error
		pp, err = p.generateProposalPaywall(u)
		if err != nil {
			return nil, err
		}
	}

	return &www.ProposalPaywallDetailsReply{
		CreditPrice:        pp.CreditPrice,
		PaywallAddress:     pp.Address,
		PaywallTxNotBefore: pp.TxNotBefore,
	}, nil
}

// processProposalPaywallPayment checks if the user has a pending paywall
// payment and returns the payment details if one is found.
func (p *politeiawww) processProposalPaywallPayment(u *user.User) (*www.ProposalPaywallPaymentReply, error) {
	log.Tracef("processProposalPaywallPayment")

	var (
		txID          string
		txAmount      uint64
		confirmations uint64
	)

	p.RLock()
	defer p.RUnlock()

	poolMember, ok := p.userPaywallPool[u.ID]
	if ok {
		txID = poolMember.txID
		txAmount = poolMember.txAmount
		confirmations = poolMember.txConfirmations
	}

	return &www.ProposalPaywallPaymentReply{
		TxID:          txID,
		TxAmount:      txAmount,
		Confirmations: confirmations,
	}, nil
}

// processAuthorizeVote sends the authorizevote command to decred plugin to
// indicate that a proposal has been finalized and is ready to be voted on.
func (p *politeiawww) processAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("processAuthorizeVote %v", av.Token)

	// Get proposal from the cache
	pr, err := p.getProp(av.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Verify signature authenticity
	err = checkPublicKeyAndSignature(u, av.PublicKey, av.Signature,
		av.Token, pr.Version, av.Action)
	if err != nil {
		return nil, err
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(av.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vd.StartVoteReply.StartBlockHeight != "":
		// Vote has already started
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != www.AuthVoteActionAuthorize &&
		av.Action != www.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == www.AuthVoteActionAuthorize &&
		voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot authorize vote; vote has already been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == www.AuthVoteActionRevoke &&
		!voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot revoke authorization; vote has not been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		p.RLock()
		userID, ok := p.userPubkeys[pr.PublicKey]
		p.RUnlock()
		if ok {
			if u.ID.String() != userID {
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusUserNotAuthor,
				}
			}
		} else {
			// This should not happen
			return nil, fmt.Errorf("proposal author not found")
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteFromWWW(av)
	payload, err := decredplugin.EncodeAuthorizeVote(dav)
	if err != nil {
		return nil, fmt.Errorf("EncodeAuthorizeVote: %v", err)
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdAuthorizeVote,
		CommandID: decredplugin.CmdAuthorizeVote + " " + av.Token,
		Payload:   string(payload),
	}

	// Send authorizevote plugin request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeAuthorizeVoteReply: %v", err)
	}

	if !p.test && avr.Action == www.AuthVoteActionAuthorize {
		p.fireEvent(EventTypeProposalVoteAuthorized,
			EventDataProposalVoteAuthorized{
				AuthorizeVote: &av,
				User:          u,
			},
		)
	}

	return &www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}, nil
}

// processStartVote handles the www.StartVote call.
func (p *politeiawww) processStartVote(sv www.StartVote, u *user.User) (*www.StartVoteReply, error) {
	log.Tracef("processStartVote %v", sv.Vote.Token)

	// Verify user
	err := checkPublicKeyAndSignature(u, sv.PublicKey, sv.Signature,
		sv.Vote.Token)
	if err != nil {
		return nil, err
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err = validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote parameters
	if sv.Vote.Duration < p.cfg.VoteDurationMin ||
		sv.Vote.Duration > p.cfg.VoteDurationMax ||
		sv.Vote.QuorumPercentage > 100 || sv.Vote.PassPercentage > 100 {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPropVoteParams,
		}
	}

	// Create vote bits as plugin payload
	dsv := convertStartVoteFromWWW(sv)
	payload, err := decredplugin.EncodeStartVote(dsv)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(sv.Vote.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	// Ensure record is public, vote has been authorized,
	// and vote has not already started.
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}
	if !voteIsAuthorized(vd.AuthorizeVoteReply) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}
	if vd.StartVoteReply.StartBlockHeight != "" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Tell decred plugin to start voting
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	vr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	p.fireEvent(EventTypeProposalVoteStarted,
		EventDataProposalVoteStarted{
			AdminUser: u,
			StartVote: &sv,
		},
	)

	// return a copy
	rv := convertStartVoteReplyFromDecred(*vr)
	return &rv, nil
}
