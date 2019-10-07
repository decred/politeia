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

// encodeMDStreamChanges encodes an MDStreamChanges into a JSON byte slice.
func encodeMDStreamChanges(m MDStreamChanges) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return b, nil
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

// tokenIsValid returns whether the provided string is a valid politeiad
// censorship record token.
func tokenIsValid(token string) bool {
	b, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	if len(b) != pd.TokenSize {
		return false
	}
	return true
}

func getInvalidTokens(tokens []string) []string {
	invalidTokens := make([]string, 0, len(tokens))

	for _, token := range tokens {
		if !tokenIsValid(token) {
			invalidTokens = append(invalidTokens, token)
		}
	}

	return invalidTokens
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
	if u.PublicKey() != np.PublicKey {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	pk, err := identity.PublicIdentityFromBytes(u.ActiveIdentity().Key[:])
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
	} else if avr.Action == decredplugin.AuthVoteActionRevoke {
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

func voteStatusFromVoteSummary(r decredplugin.VoteSummaryReply, bestBlock uint64) www.PropVoteStatusT {
	switch {
	case !r.Authorized:
		return www.PropVoteStatusNotAuthorized
	case r.EndHeight == "":
		return www.PropVoteStatusAuthorized
	default:
		endHeight, err := strconv.ParseUint(r.EndHeight, 10, 64)
		if err != nil {
			// This should not happen
			log.Errorf("voteStatusFromVoteSummary: ParseUint "+
				"failed on '%v': %v", r.EndHeight, err)
		}

		if bestBlock < endHeight {
			return www.PropVoteStatusStarted
		}

		return www.PropVoteStatusFinished
	}
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

	// Fill in proposal author info
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		log.Errorf("getProp: UserGetByPubKey: token:%v "+
			"pubKey:%v err:%v", token, pr.PublicKey, err)
	} else {
		pr.UserId = u.ID.String()
		pr.Username = u.Username
	}

	return &pr, nil
}

func (p *politeiawww) getProps(tokens []string) (*[]www.ProposalRecord, error) {
	log.Tracef("getProps: %v", tokens)

	records, err := p.cache.Records(tokens, false)
	if err != nil {
		return nil, err
	}

	props := make([]www.ProposalRecord, 0, len(tokens))
	for _, record := range records {
		props = append(props, convertPropFromCache(record))
	}

	// Find the number of comments each proposal
	dnc, err := p.decredGetNumComments(tokens)
	if err != nil {
		log.Errorf("getProp: decredGetNumComments failed "+
			"for tokens %v", tokens)
	} else {
		for i := range props {
			props[i].NumComments = uint(dnc[props[i].CensorshipRecord.Token])
		}
	}

	// Get the list of pubkeys of the proposal authors
	pubKeys := make([]string, 0, 16)
	pubKeysMap := make(map[string]bool)
	for _, pr := range props {
		if _, ok := pubKeysMap[pr.PublicKey]; !ok {
			pubKeysMap[pr.PublicKey] = true
			pubKeys = append(pubKeys, pr.PublicKey)
		}
	}

	// Fill in proposal author info
	users, err := p.db.UsersGetByPubKey(pubKeys)
	if err != nil {
		log.Errorf("getProps: UsersGetByPubKey: tokens:%v "+
			"pubKeys:%v err:%v", tokens, pubKeys, err)
	} else {
		for i := range props {
			props[i].UserId = users[props[i].PublicKey].ID.String()
			props[i].Username = users[props[i].PublicKey].Username
		}
	}

	return &props, nil
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

	// Fill in proposal author info
	u, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		log.Errorf("getPropVersion: UserGetByPubKey: pubKey:%v "+
			"token:%v err:%v", pr.PublicKey, token, err)
	} else {
		pr.UserId = u.ID.String()
		pr.Username = u.Username
	}

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

	// Convert props and fill in missing info
	props := make([]www.ProposalRecord, 0, len(records))
	for _, v := range records {
		pr := convertPropFromCache(v)

		// Fill in num comments
		dc, err := p.decredGetComments(pr.CensorshipRecord.Token)
		if err != nil {
			log.Errorf("getAllProps: decredGetComments failed "+
				"for token %v", pr.CensorshipRecord.Token)
		}
		pr.NumComments = uint(len(dc))

		// Fill in author info
		u, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			log.Errorf("getAllProps: UserGetByPubKey: token:%v "+
				"pubKey:%v", pr.CensorshipRecord.Token, pr.PublicKey)
		} else {
			pr.UserId = u.ID.String()
			pr.Username = u.Username
		}

		props = append(props, pr)
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

	// Convert comments and fill in author info
	comments := make([]www.Comment, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getPropComments: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		} else {
			c.UserID = u.ID.String()
			c.Username = u.Username
		}
		comments = append(comments, c)
	}

	// Fill in comment scores
	p.RLock()
	defer p.RUnlock()

	for i, v := range comments {
		votes, ok := p.commentVotes[v.Token+v.CommentID]
		if !ok {
			log.Errorf("getPropComments: comment votes lookup "+
				"failed: token:%v commentID:%v pubKey:%v", v.Token,
				v.CommentID, v.PublicKey)
		}
		comments[i].ResultVotes = int64(votes.up - votes.down)
		comments[i].Upvotes = votes.up
		comments[i].Downvotes = votes.down
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

// cacheVoteSumamary stores a given VoteSummary in memory.  This is to only
// be used for proposals whose voting period has ended so that we don't have
// to worry about cache invalidation issues.
//
// This function must be called without the lock held.
func (p *politeiawww) cacheVoteSummary(token string, voteSummary www.VoteSummary) {
	p.Lock()
	defer p.Unlock()

	p.voteSummaries[token] = voteSummary
}

// getVoteSummaries fetches the voting summary information for a set of
// proposals.
func (p *politeiawww) getVoteSummaries(tokens []string, bestBlock uint64) (map[string]www.VoteSummary, error) {
	voteSummaries := make(map[string]www.VoteSummary)
	tokensToLookup := make([]string, 0, len(tokens))

	p.RLock()
	for _, token := range tokens {
		vs, ok := p.voteSummaries[token]
		if ok {
			voteSummaries[token] = vs
		} else {
			tokensToLookup = append(tokensToLookup, token)
		}
	}
	p.RUnlock()

	if len(tokensToLookup) == 0 {
		return voteSummaries, nil
	}

	r, err := p.decredBatchVoteSummary(tokensToLookup)
	if err != nil {
		return nil, err
	}

	for token, summary := range r.Summaries {
		results := convertVoteOptionResultsFromDecred(summary.Results)

		// An endHeight will not exist if the proposal has not gone
		// up for vote yet.
		var endHeight uint64
		if summary.EndHeight != "" {
			i, err := strconv.ParseUint(summary.EndHeight, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse end height "+
					"'%v' for %v: %v", summary.EndHeight, token, err)
			}
			endHeight = i
		}

		vs := www.VoteSummary{
			Status:           voteStatusFromVoteSummary(summary, bestBlock),
			EligibleTickets:  uint32(summary.EligibleTicketCount),
			Duration:         summary.Duration,
			EndHeight:        endHeight,
			QuorumPercentage: summary.QuorumPercentage,
			PassPercentage:   summary.PassPercentage,
			Results:          results,
		}

		voteSummaries[token] = vs

		// If the voting period has ended the vote status
		// is not going to change so add it to the memory
		// cache.
		if vs.Status == www.PropVoteStatusFinished {
			p.cacheVoteSummary(token, vs)
		}
	}

	return voteSummaries, nil
}

// processBatchVoteSummary returns the vote summaries for the provided list
// of proposals.
func (p *politeiawww) processBatchVoteSummary(batchVoteSummary www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary")

	if len(batchVoteSummary.Tokens) > www.ProposalListPageSize {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMaxProposalsExceededPolicy,
		}
	}

	invalidTokens := getInvalidTokens(batchVoteSummary.Tokens)
	if len(invalidTokens) > 0 {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: invalidTokens,
		}
	}

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	summaries, err := p.getVoteSummaries(batchVoteSummary.Tokens, bb)
	if err != nil {
		return nil, err
	}

	if len(summaries) != len(batchVoteSummary.Tokens) {
		tokensNotFound := make([]string, 0,
			len(batchVoteSummary.Tokens)-len(summaries))

		for _, token := range batchVoteSummary.Tokens {
			if _, exists := summaries[token]; !exists {
				tokensNotFound = append(tokensNotFound, token)
			}
		}

		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusProposalNotFound,
			ErrorContext: tokensNotFound,
		}
	}

	return &www.BatchVoteSummaryReply{
		BestBlock: bb,
		Summaries: summaries,
	}, nil
}

// processBatchProposals fetches a list of proposals from the records
// cache and returns them. The returned proposals do not include the
// proposal files.
func (p *politeiawww) processBatchProposals(batchProposals www.BatchProposals, user *user.User) (*www.BatchProposalsReply, error) {
	log.Tracef("processBatchProposals")

	if len(batchProposals.Tokens) > www.ProposalListPageSize {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMaxProposalsExceededPolicy,
		}
	}

	props, err := p.getProps(batchProposals.Tokens)
	if err != nil {
		return nil, err
	}

	if len(*props) != len(batchProposals.Tokens) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	reply := www.BatchProposalsReply{
		Proposals: *props,
	}

	for i := range *props {
		// Vetted proposals are viewable by everyone. The contents of
		// an unvetted proposal is only viewable by admins and the
		// proposal author. Unvetted proposal metadata is viewable by
		// everyone.
		if reply.Proposals[i].State == www.PropStateUnvetted {
			var isAuthor bool
			var isAdmin bool
			// This is a public route so a user may not exist
			if user != nil {
				isAdmin = user.Admin
				isAuthor = (reply.Proposals[i].UserId == user.ID.String())
			}

			// Strip the non-public proposal contents if user is
			// not the author or an admin. The files are already
			// not included in this request.
			if !isAuthor && !isAdmin {
				reply.Proposals[i].Name = ""
			}
		}
	}

	return &reply, nil
}

// verifyStatusChange verifies that the proposal status change is a valid
// status transition.  This only applies to manual status transitions that are
// initiated by an admin.  It does not apply to status changes that are caused
// by editing a proposal.
func verifyStatusChange(current, next www.PropStatusT) error {
	var err error
	switch {
	case current == www.PropStatusNotReviewed &&
		(next == www.PropStatusCensored ||
			next == www.PropStatusPublic):
	// allowed; continue
	case current == www.PropStatusUnreviewedChanges &&
		(next == www.PropStatusCensored ||
			next == www.PropStatusPublic):
		// allowed; continue
	case current == www.PropStatusPublic &&
		next == www.PropStatusAbandoned:
		// allowed; continue
	default:
		err = www.UserError{
			ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
		}
	}
	return err
}

// processSetProposalStatus changes the status of an existing proposal.
func (p *politeiawww) processSetProposalStatus(sps www.SetProposalStatus, u *user.User) (*www.SetProposalStatusReply, error) {
	log.Tracef("processSetProposalStatus %v", sps.Token)

	// Ensure the status change message is not blank if the
	// proposal is being censored or abandoned.
	if sps.StatusChangeMessage == "" &&
		(sps.ProposalStatus == www.PropStatusCensored ||
			sps.ProposalStatus == www.PropStatusAbandoned) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
		}
	}

	// Ensure the provided public key is the user's active key.
	if sps.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := sps.Token + strconv.Itoa(int(sps.ProposalStatus)) +
		sps.StatusChangeMessage
	err := validateSignature(sps.PublicKey, sps.Signature, msg)
	if err != nil {
		return nil, err
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
		author, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			return nil, err
		}
		if author.ID.String() == u.ID.String() {
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

	// Ensure status change is allowed
	err = verifyStatusChange(pr.Status, sps.ProposalStatus)
	if err != nil {
		return nil, err
	}

	var challengeResponse string
	switch {
	case pr.State == www.PropStateUnvetted:
		// Unvetted status change

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

		// Ensure voting has not been started or authorized yet
		vdr, err := p.decredVoteDetails(pr.CensorshipRecord.Token)
		if err != nil {
			return nil, fmt.Errorf("decredVoteDetails: %v", err)
		}
		vd := convertVoteDetailsReplyFromDecred(*vdr)

		switch {
		case vd.StartVoteReply.StartBlockHeight != "":
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}
		case voteIsAuthorized(vd.AuthorizeVoteReply):
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
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
		panic(fmt.Sprintf("invalid proposal state %v %v",
			pr.CensorshipRecord.Token, pr.State))
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

	// Check for changes in the index.md file
	var newMDFile www.File
	for _, v := range ep.Files {
		if v.Name == indexFile {
			newMDFile = v
		}
	}

	var oldMDFile www.File
	for _, v := range cachedProp.Files {
		if v.Name == indexFile {
			oldMDFile = v
		}
	}

	mdChanges := newMDFile.Payload != oldMDFile.Payload

	// Check that the proposal has been changed
	if !mdChanges && len(delFiles) == 0 &&
		len(cachedProp.Files) == len(ep.Files) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalChanges,
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

	// Validate query params
	if (v.Before != "" && !tokenIsValid(v.Before)) ||
		(v.After != "" && !tokenIsValid(v.After)) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}

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

// setVoteStatusReply converts a VoteStatusReply to a VoteSummary and stores it
// in memory.  This is to only be used for proposals whose voting period has
// ended so that we don't have to worry about cache invalidation issues.
//
// This function must be called without the lock held.
//
// ** This fuction is to be removed when the deprecated vote status route is
// ** removed.
func (p *politeiawww) setVoteStatusReply(v www.VoteStatusReply) error {
	p.Lock()
	defer p.Unlock()

	endHeight, err := strconv.Atoi(v.EndHeight)
	if err != nil {
		return err
	}

	voteSummary := www.VoteSummary{
		Status:           v.Status,
		EligibleTickets:  uint32(v.NumOfEligibleVotes),
		EndHeight:        uint64(endHeight),
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Results:          v.OptionsResult,
	}

	p.voteSummaries[v.Token] = voteSummary

	return nil
}

// getVoteStatusReply retrieves the VoteSummary from the cache for a proposal
// whose voting period has ended and converts it to a VoteStatusReply.
//
// This function must be called without the lock held.
//
// ** This fuction is to be removed when the deprecated vote status route is
// ** removed.
func (p *politeiawww) getVoteStatusReply(token string) (*www.VoteStatusReply, bool) {
	p.RLock()
	vs, ok := p.voteSummaries[token]
	p.RUnlock()

	if !ok {
		return nil, false
	}

	var totalVotes uint64
	for _, or := range vs.Results {
		totalVotes += or.VotesReceived
	}

	voteStatusReply := www.VoteStatusReply{
		Token:              token,
		Status:             vs.Status,
		TotalVotes:         totalVotes,
		OptionsResult:      vs.Results,
		EndHeight:          strconv.Itoa(int(vs.EndHeight)),
		NumOfEligibleVotes: int(vs.EligibleTickets),
		QuorumPercentage:   vs.QuorumPercentage,
		PassPercentage:     vs.PassPercentage,
	}

	return &voteStatusReply, true
}

func (p *politeiawww) voteStatusReply(token string, bestBlock uint64) (*www.VoteStatusReply, error) {
	cachedVsr, ok := p.getVoteStatusReply(token)

	if ok {
		cachedVsr.BestBlock = strconv.Itoa(int(bestBlock))
		return cachedVsr, nil
	}

	// Vote status wasn't in the memory cache
	// so fetch it from the cache database.
	r, err := p.decredVoteSummary(token)
	if err != nil {
		return nil, err
	}

	results := convertVoteOptionResultsFromDecred(r.Results)
	var total uint64
	for _, v := range results {
		total += v.VotesReceived
	}

	voteStatusReply := www.VoteStatusReply{
		Token:              token,
		Status:             voteStatusFromVoteSummary(*r, bestBlock),
		TotalVotes:         total,
		OptionsResult:      results,
		EndHeight:          r.EndHeight,
		BestBlock:          strconv.Itoa(int(bestBlock)),
		NumOfEligibleVotes: r.EligibleTicketCount,
		QuorumPercentage:   r.QuorumPercentage,
		PassPercentage:     r.PassPercentage,
	}

	// If the voting period has ended the vote status
	// is not going to change so add it to the memory
	// cache.
	if voteStatusReply.Status == www.PropVoteStatusFinished {
		err = p.setVoteStatusReply(voteStatusReply)
		if err != nil {
			return nil, err
		}
	}

	return &voteStatusReply, nil
}

// processVoteStatus returns the vote status for a given proposal
func (p *politeiawww) processVoteStatus(token string) (*www.VoteStatusReply, error) {
	log.Tracef("ProcessProposalVotingStatus: %v", token)

	// Ensure proposal is vetted
	pr, err := p.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.State != www.PropStateVetted {
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
	vsr, err := p.voteStatusReply(token, bestBlock)
	if err != nil {
		return nil, fmt.Errorf("voteStatusReply: %v", err)
	}

	return vsr, nil
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
		vs, err := p.voteStatusReply(v.CensorshipRecord.Token, bestBlock)
		if err != nil {
			return nil, fmt.Errorf("voteStatusReply: %v", err)
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

	// Ensure proposal is vetted
	pr, err := p.getProp(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.State != www.PropStateVetted {
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

	// Ensure the public key is the user's active key
	if av.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := av.Token + pr.Version + av.Action
	err = validateSignature(av.PublicKey, av.Signature, msg)
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
	case av.Action != decredplugin.AuthVoteActionAuthorize &&
		av.Action != decredplugin.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == decredplugin.AuthVoteActionAuthorize &&
		voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot authorize vote; vote has already been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == decredplugin.AuthVoteActionRevoke &&
		!voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot revoke authorization; vote has not been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		usr, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			return nil, err
		}
		if u.ID.String() != usr.ID.String() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			}
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

	if !p.test && avr.Action == decredplugin.AuthVoteActionAuthorize {
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

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	err := validateSignature(sv.PublicKey, sv.Signature, sv.Vote.Token)
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

// processTokenInventory returns the tokens of all proposals in the inventory,
// categorized by stage of the voting process.
func (p *politeiawww) processTokenInventory(isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// The vote results cache table is lazy loaded and may
	// need to be updated. If it does need to be updated, the
	// token inventory call will need to be retried after the
	// update is complete.
	var done bool
	var r www.TokenInventoryReply
	for retries := 0; !done && retries <= 1; retries++ {
		// Both vetted and unvetted tokens should be returned
		// for admins. Only vetted tokens should be returned
		// for non-admins.
		ti, err := p.decredTokenInventory(bb, isAdmin)
		if err != nil {
			if err == cache.ErrRecordNotFound {
				// There are missing entries in the vote
				// results cache table. Load them.
				_, err := p.decredLoadVoteResults(bb)
				if err != nil {
					return nil, err
				}

				// Retry token inventory call
				continue
			}
			return nil, err
		}

		r = convertTokenInventoryReplyFromDecred(*ti)
		done = true
	}

	return &r, err
}
