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

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/user"
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

// isProposalAuthor returns whether the provided user is the author of the
// provided proposal.
func isProposalAuthor(pr www.ProposalRecord, u user.User) bool {
	var isAuthor bool
	for _, v := range u.Identities {
		if v.String() == pr.PublicKey {
			isAuthor = true
		}
	}
	return isAuthor
}

// isRFP returns whether the proposal is a Request For Proposals (RFP).
func isRFP(pr www.ProposalRecord) bool {
	return pr.LinkBy != 0
}

func isRFPSubmission(pr www.ProposalRecord) bool {
	// Right now the only proposals that we allow linking to
	// are RFPs so if the linkto is set than this is an RFP
	// submission. This may change in the future, at which
	// point we'll actually have to check the linkto proposal
	// to see if its an RFP.
	return pr.LinkTo != ""
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
func validateVoteBit(vote www2.Vote, bit uint64) error {
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

func (p *politeiawww) linkByValidate(linkBy int64) error {
	min := time.Now().Unix() + p.linkByPeriodMin()
	max := time.Now().Unix() + p.linkByPeriodMax()
	switch {
	case linkBy < min:
		e := fmt.Sprintf("linkby %v is less than min required of %v",
			linkBy, min)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkBy,
			ErrorContext: []string{e},
		}
	case linkBy > max:
		e := fmt.Sprintf("linkby %v is more than max allowed of %v",
			linkBy, max)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidLinkBy,
			ErrorContext: []string{e},
		}
	}
	return nil
}

func voteStatusFromVoteSummary(r decredplugin.VoteSummaryReply, endHeight, bestBlock uint64) www.PropVoteStatusT {
	switch {
	case !r.Authorized:
		return www.PropVoteStatusNotAuthorized
	case r.Authorized && endHeight == 0:
		return www.PropVoteStatusAuthorized
	case bestBlock < endHeight:
		return www.PropVoteStatusStarted
	case bestBlock >= endHeight:
		return www.PropVoteStatusFinished
	}

	return www.PropVoteStatusInvalid
}

func (p *politeiawww) getProp(token string) (*www.ProposalRecord, error) {
	return nil, nil
}

func (p *politeiawww) getProps(tokens []string) (map[string]www.ProposalRecord, error) {
	return nil, nil
}

func (p *politeiawww) getPropVersion(token, version string) (*www.ProposalRecord, error) {
	return nil, nil
}

func (p *politeiawww) getAllProps() ([]www.ProposalRecord, error) {
	return nil, nil
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

func (p *politeiawww) processProposalDetails(pd www.ProposalsDetails, u *user.User) (*www.ProposalDetailsReply, error) {
	return nil, nil
}

func (p *politeiawww) processBatchVoteSummary(bvs www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	return nil, nil
}

func (p *politeiawww) processBatchProposals(bp www.BatchProposals, u *user.User) (*www.BatchProposalsReply, error) {
	return nil, nil
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
	// TODO do not use getAllProps
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
	return nil, nil
}

func (p *politeiawww) processAllVetted(v www.GetAllVetted) (*www.GetAllVettedReply, error) {
	return nil, nil
}

func (p *politeiawww) processCommentsGet(token string, u *user.User) (*www.GetCommentsReply, error) {
	return nil, nil
}

func (p *politeiawww) processVoteStatus(token string) (*www.VoteStatusReply, error) {
	return nil, nil
}

func (p *politeiawww) processGetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	return nil, nil
}

func (p *politeiawww) processActiveVote() (*www.ActiveVoteReply, error) {
	return nil, nil
}

func (p *politeiawww) processVoteResults(token string) (*www.VoteResultsReply, error) {
	return nil, nil
}

func (p *politeiawww) processCastVotes(ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	// Verify proposal tokens
	for _, vote := range ballot.Votes {
		if !tokenIsValid(vote.Token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{vote.Token},
			}
		}
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
	if !p.userHasPaid(*u) {
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

// validateAuthorizeVote validates the authorize vote fields. A UserError is
// returned if any of the validation fails.
func validateAuthorizeVote(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	// Ensure the public key is the user's active key
	if av.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := av.Token + pr.Version + av.Action
	err := validateSignature(av.PublicKey, av.Signature, msg)
	if err != nil {
		return err
	}

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != decredplugin.AuthVoteActionAuthorize &&
		av.Action != decredplugin.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == decredplugin.AuthVoteActionAuthorize &&
		vs.Status == www.PropVoteStatusAuthorized:
		// Cannot authorize vote; vote has already been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == decredplugin.AuthVoteActionRevoke &&
		vs.Status != www.PropVoteStatusAuthorized:
		// Cannot revoke authorization; vote has not been authorized
		return www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}

	return nil
}

// validateAuthorizeVoteStandard validates the authorize vote for a proposal that
// is participating in a standard vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteStandard(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateAuthorizeVote(av, u, pr, vs)
	if err != nil {
		return err
	}

	// The rest of the validation is specific to authorize votes for
	// standard votes.
	switch {
	case isRFPSubmission(pr):
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{"proposal is an rfp submission"},
		}
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		if !isProposalAuthor(pr, u) {
			return www.UserError{
				ErrorCode: www.ErrorStatusUserNotAuthor,
			}
		}
	}

	return nil
}

// validateAuthorizeVoteRunoff validates the authorize vote for a proposal that
// is participating in a runoff vote. A UserError is returned if any of the
// validation fails.
func validateAuthorizeVoteRunoff(av www.AuthorizeVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateAuthorizeVote(av, u, pr, vs)
	if err != nil {
		return err
	}

	// The rest of the validation is specific to authorize votes for
	// runoff votes.
	switch {
	case !u.Admin:
		// User is not an admin
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidSigningKey,
			ErrorContext: []string{"user not an admin"},
		}
	}

	return nil
}

func (p *politeiawww) voteSummaryGet(token string, bestBlock uint64) (*www.VoteSummary, error) {
	return nil, nil
}

// processAuthorizeVote sends the authorizevote command to decred plugin to
// indicate that a proposal has been finalized and is ready to be voted on.
func (p *politeiawww) processAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("processAuthorizeVote %v", av.Token)

	// Make sure token is valid and not a prefix
	if !tokenIsValid(av.Token) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: []string{av.Token},
		}
	}

	// Validate the vote authorization
	pr, err := p.getProp(av.Token)
	if err != nil {
		/*
			// TODO
			if err == cache.ErrRecordNotFound {
				err = www.UserError{
					ErrorCode: www.ErrorStatusProposalNotFound,
				}
			}
		*/
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(av.Token, bb)
	if err != nil {
		return nil, err
	}
	err = validateAuthorizeVoteStandard(av, *u, *pr, *vs)
	if err != nil {
		return nil, err
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteToDecred(av)
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
		// Emit event notification for proposal vote authorized
		p.eventManager.emit(eventProposalVoteAuthorized,
			dataProposalVoteAuthorized{
				token:    av.Token,
				name:     pr.Name,
				username: u.Username,
				email:    u.Email,
			})
	}

	return &www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}, nil
}

// validateVoteOptions verifies that the provided vote options
// specify a simple approve/reject vote and nothing else. A UserError is
// returned if this validation fails.
func validateVoteOptions(options []www2.VoteOption) error {
	if len(options) == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteOptions,
			ErrorContext: []string{"no vote options found"},
		}
	}
	optionIDs := map[string]bool{
		decredplugin.VoteOptionIDApprove: false,
		decredplugin.VoteOptionIDReject:  false,
	}
	for _, vo := range options {
		if _, ok := optionIDs[vo.Id]; !ok {
			e := fmt.Sprintf("invalid vote option id '%v'", vo.Id)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
		optionIDs[vo.Id] = true
	}
	for k, wasFound := range optionIDs {
		if !wasFound {
			e := fmt.Sprintf("missing vote option id '%v'", k)
			return www.UserError{
				ErrorCode:    www.ErrorStatusInvalidVoteOptions,
				ErrorContext: []string{e},
			}
		}
	}
	return nil
}

func validateStartVote(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	if !tokenIsValid(sv.Vote.Token) {
		// Sanity check since proposal has already been looked up and
		// passed in to this function.
		return fmt.Errorf("invalid token %v", sv.Vote.Token)
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err := validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			log.Debugf("validateStartVote: validateVoteBit '%v': %v",
				v.Id, err)
			return www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote options. Only simple yes/no votes are currently
	// allowed.
	err := validateVoteOptions(sv.Vote.Options)
	if err != nil {
		return err
	}

	// Validate vote params
	switch {
	case sv.Vote.Duration < durationMin:
		// Duration not large enough
		e := fmt.Sprintf("vote duration must be >= %v", durationMin)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.Duration > durationMax:
		// Duration too large
		e := fmt.Sprintf("vote duration must be <= %v", durationMax)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{e},
		}
	case sv.Vote.QuorumPercentage > 100:
		// Quorum too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"quorum percentage cannot be >100"},
		}
	case sv.Vote.PassPercentage > 100:
		// Pass percentage too large
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidPropVoteParams,
			ErrorContext: []string{"pass percentage cannot be >100"},
		}
	}

	// Ensure the public key is the user's active key
	if sv.PublicKey != u.PublicKey() {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	dsv := convertStartVoteV2ToDecred(sv)
	err = dsv.VerifySignature()
	if err != nil {
		log.Debugf("validateStartVote: VerifySignature: %v", err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Validate proposal
	votePropVersion := strconv.FormatUint(uint64(sv.Vote.ProposalVersion), 10)
	switch {
	case pr.Version != votePropVersion:
		// Vote is specifying the wrong version
		e := fmt.Sprintf("got %v, want %v", votePropVersion, pr.Version)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidProposalVersion,
			ErrorContext: []string{e},
		}
	case pr.Status != www.PropStatusPublic:
		// Proposal is not public
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"proposal is not public"},
		}
	case vs.EndHeight != 0:
		// Vote has already started
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote already started"},
		}
	}

	return nil
}

func (p *politeiawww) validateStartVoteStandard(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary) error {
	err := validateStartVote(sv, u, pr, vs, p.cfg.VoteDurationMin,
		p.cfg.VoteDurationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeStandard.
	switch {
	case sv.Vote.Type != www2.VoteTypeStandard:
		// Not a standard vote
		e := fmt.Sprintf("vote type must be %v", www2.VoteTypeStandard)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}
	case vs.Status != www.PropVoteStatusAuthorized:
		// Vote has not been authorized
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote not authorized"},
		}
	case isRFPSubmission(pr):
		// The proposal is an an RFP submission. The voting period for
		// RFP submissions can only be started using the StartVoteRunoff
		// route.
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{"cannot be an rfp submission"},
		}
	}

	// Verify the LinkBy deadline for RFP proposals. The LinkBy policy
	// requirements are enforced at the time of starting the vote
	// because its purpose is to ensure that there is enough time for
	// RFP submissions to be submitted.
	if isRFP(pr) {
		err := p.linkByValidate(pr.LinkBy)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateStartVoteRunoff(sv www2.StartVote, u user.User, pr www.ProposalRecord, vs www.VoteSummary, durationMin, durationMax uint32) error {
	err := validateStartVote(sv, u, pr, vs, durationMin, durationMax)
	if err != nil {
		return err
	}

	// The remaining validation is specific to a VoteTypeRunoff.

	token := sv.Vote.Token
	switch {
	case sv.Vote.Type != www2.VoteTypeRunoff:
		// Not a runoff vote
		e := fmt.Sprintf("%v vote type must be %v",
			token, www2.VoteTypeRunoff)
		return www.UserError{
			ErrorCode:    www.ErrorStatusInvalidVoteType,
			ErrorContext: []string{e},
		}

	case !isRFPSubmission(pr):
		// The proposal is not an RFP submission
		e := fmt.Sprintf("%v is not an rfp submission", token)
		return www.UserError{
			ErrorCode:    www.ErrorStatusWrongProposalType,
			ErrorContext: []string{e},
		}

	case vs.Status != www.PropVoteStatusNotAuthorized:
		// Sanity check. This should not be possible.
		return fmt.Errorf("%v got vote status %v, want %v",
			token, vs.Status, www.PropVoteStatusNotAuthorized)
	}

	return nil
}

// processStartVoteV2 starts the voting period on a proposal using the provided
// v2 StartVote. Proposals that are RFP submissions cannot use this route. They
// must sue the StartVoteRunoff route.
func (p *politeiawww) processStartVoteV2(sv www2.StartVote, u *user.User) (*www2.StartVoteReply, error) {
	log.Tracef("processStartVoteV2 %v", sv.Vote.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Fetch proposal and vote summary
	if !tokenIsValid(sv.Vote.Token) {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
			ErrorContext: []string{sv.Vote.Token},
		}
	}
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		/*
			// TODO
			if err == cache.ErrRecordNotFound {
				err = www.UserError{
					ErrorCode: www.ErrorStatusProposalNotFound,
				}
			}
		*/
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}
	vs, err := p.voteSummaryGet(sv.Vote.Token, bb)
	if err != nil {
		return nil, err
	}

	// Validate the start vote
	err = p.validateStartVoteStandard(sv, *u, *pr, *vs)
	if err != nil {
		return nil, err
	}

	// Tell decred plugin to start voting
	dsv := convertStartVoteV2ToDecred(sv)
	payload, err := decredplugin.EncodeStartVoteV2(dsv)
	if err != nil {
		return nil, err
	}
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

	// Handle reply
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(*dsvr)
	if err != nil {
		return nil, err
	}

	// Get author data
	author, err := p.db.UserGetByPubKey(pr.PublicKey)
	if err != nil {
		return nil, err
	}

	// Emit event notification for proposal start vote
	p.eventManager.emit(eventProposalVoteStarted,
		dataProposalVoteStarted{
			token:   pr.CensorshipRecord.Token,
			name:    pr.Name,
			adminID: u.ID.String(),
			author:  *author,
		})

	return svr, nil
}

// voteIsApproved returns whether the provided VoteSummary met the quorum
// and pass requirements. This function should only be called on simple
// approve/reject votes that use the decredplugin VoteOptionIDApprove.
func voteIsApproved(vs www.VoteSummary) bool {
	if vs.Status != www.PropVoteStatusFinished {
		// Vote has not ended yet
		return false
	}

	var (
		total   uint64
		approve uint64
	)
	for _, v := range vs.Results {
		total += v.VotesReceived
		if v.Option.Id == decredplugin.VoteOptionIDApprove {
			approve = v.VotesReceived
		}
	}
	quorum := uint64(float64(vs.QuorumPercentage) / 100 * float64(vs.EligibleTickets))
	pass := uint64(float64(vs.PassPercentage) / 100 * float64(total))
	switch {
	case total < quorum:
		// Quorum not met
		return false
	case approve < pass:
		// Pass percentage not met
		return false
	}

	return true
}

// processStartVoteRunoffV2 starts the runoff voting process on all public,
// non-abandoned RFP submissions for the provided RFP token. If politeiad fails
// to start the voting period on any of the RFP submissions, all work is
// unwound and an error is returned.
func (p *politeiawww) processStartVoteRunoffV2(sv www2.StartVoteRunoff, u *user.User) (*www2.StartVoteRunoffReply, error) {
	log.Tracef("processStartVoteRunoffV2 %v", sv.Token)

	// Sanity check
	if !u.Admin {
		return nil, fmt.Errorf("user is not an admin")
	}

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	// Ensure authorize votes and start votes match
	auths := make(map[string]www2.AuthorizeVote, len(sv.AuthorizeVotes))
	starts := make(map[string]www2.StartVote, len(sv.StartVotes))
	for _, v := range sv.AuthorizeVotes {
		auths[v.Token] = v
	}
	for _, v := range sv.StartVotes {
		_, ok := auths[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("start vote found without matching authorize vote %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	for _, v := range sv.StartVotes {
		starts[v.Vote.Token] = v
	}
	for _, v := range sv.AuthorizeVotes {
		_, ok := starts[v.Token]
		if !ok {
			e := fmt.Sprintf("authorize vote found without matching start vote %v",
				v.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}
	if len(auths) == 0 {
		e := "start votes and authorize votes cannot be empty"
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusInvalidRunoffVote,
			ErrorContext: []string{e},
		}
	}

	// Slice used to send event notification for each proposal
	// starting a vote, at the end of this function.
	var proposalNotifications []*www.ProposalRecord

	// Validate authorize votes and start votes
	for _, v := range sv.StartVotes {
		// Fetch proposal and vote summary
		token := v.Vote.Token
		if !tokenIsValid(token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{token},
			}
		}
		pr, err := p.getProp(token)
		if err != nil {
			/*
				// TODO
				if err == cache.ErrRecordNotFound {
					err = www.UserError{
						ErrorCode:    www.ErrorStatusProposalNotFound,
						ErrorContext: []string{token},
					}
				}
			*/
			return nil, err
		}

		proposalNotifications = append(proposalNotifications, pr)

		vs, err := p.voteSummaryGet(token, bb)
		if err != nil {
			return nil, err
		}

		// Validate authorize vote. The validation function requires a v1
		// AuthorizeVote. This is fine. There is no difference between v1
		// and v2.
		av := auths[v.Vote.Token]
		av1 := www.AuthorizeVote{
			Token:     av.Token,
			Action:    av.Action,
			PublicKey: av.PublicKey,
			Signature: av.Signature,
		}
		err = validateAuthorizeVoteRunoff(av1, *u, *pr, *vs)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			if ue, ok := err.(*www.UserError); ok {
				ue.ErrorContext = append(ue.ErrorContext, token)
				err = ue
			}
			return nil, err
		}

		// Validate start vote
		err = validateStartVoteRunoff(v, *u, *pr, *vs,
			p.cfg.VoteDurationMin, p.cfg.VoteDurationMax)
		if err != nil {
			// Attach the token to the error so the user knows which one
			// failed.
			if ue, ok := err.(*www.UserError); ok {
				ue.ErrorContext = append(ue.ErrorContext, token)
				err = ue
			}
			return nil, err
		}
	}

	// Validate the RFP proposal
	rfp, err := p.getProp(sv.Token)
	if err != nil {
		/*
			// TODO
			if err == cache.ErrRecordNotFound {
				err = www.UserError{
					ErrorCode:    www.ErrorStatusProposalNotFound,
					ErrorContext: []string{sv.Token},
				}
			}
		*/
		return nil, err
	}
	switch {
	case rfp.LinkBy > time.Now().Unix() && !p.cfg.TestNet:
		// Vote cannot start on RFP submissions until the RFP linkby
		// deadline has been met. This validation is skipped when on
		// testnet.
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusLinkByDeadlineNotMet,
		}
	case len(rfp.LinkedFrom) == 0:
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoLinkedProposals,
		}
	}

	// Compile a list of the public, non-abandoned RFP submissions.
	// This list will be used to ensure a StartVote exists for each
	// of the public, non-abandoned submissions.
	linkedFromProps, err := p.getProps(rfp.LinkedFrom)
	if err != nil {
		return nil, err
	}
	submissions := make(map[string]bool, len(rfp.LinkedFrom)) // [token]startVoteFound
	for _, v := range linkedFromProps {
		// Filter out abandoned submissions. These are not allowed
		// to be included in a runoff vote.
		if v.Status != www.PropStatusPublic {
			continue
		}

		// Set to false for now until we check that a StartVote
		// was included for this proposal.
		submissions[v.CensorshipRecord.Token] = false
	}

	// Verify that a StartVote exists for all public, non-abandoned
	// submissions and that there are no extra StartVotes.
	for _, v := range sv.StartVotes {
		_, ok := submissions[v.Vote.Token]
		if !ok {
			e := fmt.Sprintf("invalid start vote submission: %v",
				v.Vote.Token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}

		// A StartVote was included for this proposal
		submissions[v.Vote.Token] = true
	}
	for token, startVoteFound := range submissions {
		if !startVoteFound {
			e := fmt.Sprintf("missing start vote for rfp submission: %v",
				token)
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidRunoffVote,
				ErrorContext: []string{e},
			}
		}
	}

	// Setup plugin command
	dav := convertAuthorizeVotesV2ToDecred(sv.AuthorizeVotes)
	dsv := convertStartVotesV2ToDecred(sv.StartVotes)
	payload, err := decredplugin.EncodeStartVoteRunoff(
		decredplugin.StartVoteRunoff{
			Token:          sv.Token,
			AuthorizeVotes: dav,
			StartVotes:     dsv,
		})
	if err != nil {
		return nil, err
	}
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVoteRunoff,
		Payload:   string(payload),
	}

	// Send plugin command
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}
	dsvr, err := decredplugin.DecodeStartVoteRunoffReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	svr, err := convertStartVoteReplyV2FromDecred(dsvr.StartVoteReply)
	if err != nil {
		return nil, err
	}

	// Emit event notification for each proposal starting vote
	for _, pn := range proposalNotifications {
		author, err := p.db.UserGetByPubKey(pn.PublicKey)
		if err != nil {
			return nil, err
		}
		p.eventManager.emit(eventProposalVoteStarted,
			dataProposalVoteStarted{
				token:   pn.CensorshipRecord.Token,
				name:    pn.Name,
				adminID: u.ID.String(),
				author:  *author,
			})
	}

	return &www2.StartVoteRunoffReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndBlockHeight,
		EligibleTickets:  svr.EligibleTickets,
	}, nil
}

// tokenInventory fetches the token inventory from the cache and returns a
// TokenInventoryReply. This call relies on the lazy loaded VoteResults cache
// table. If the VoteResults table is not up-to-date then this function will
// load it before retrying the token inventory call. Since politeiawww only has
// read access to the cache, loading the VoteResults table requires using a
// politeiad decredplugin command.
func (p *politeiawww) tokenInventory(bestBlock uint64, isAdmin bool) (*www.TokenInventoryReply, error) {
	/*
		var done bool
		var r www.TokenInventoryReply
		for retries := 0; !done && retries <= 1; retries++ {
			// Both vetted and unvetted tokens should be returned
			// for admins. Only vetted tokens should be returned
			// for non-admins.
			ti, err := p.decredTokenInventory(bestBlock, isAdmin)
			if err != nil {
				if err == cache.ErrRecordNotFound {
					// There are missing entries in the vote
					// results cache table. Load them.
					_, err := p.decredLoadVoteResults(bestBlock)
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

		return &r, nil
	*/

	return nil, nil
}

// processTokenInventory returns the tokens of all proposals in the inventory,
// categorized by stage of the voting process.
func (p *politeiawww) processTokenInventory(isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, err
	}

	return p.tokenInventory(bb, isAdmin)
}

// processVoteDetailsV2 returns the vote details for the given proposal token.
func (p *politeiawww) processVoteDetailsV2(token string) (*www2.VoteDetailsReply, error) {
	log.Tracef("processVoteDetailsV2: %v", token)

	/*
		// Validate vote status
		dvdr, err := p.decredVoteDetails(token)
		if err != nil {
				if err == cache.ErrRecordNotFound {
					err = www.UserError{
						ErrorCode: www.ErrorStatusProposalNotFound,
					}
				}
			return nil, err
		}
		if dvdr.StartVoteReply.StartBlockHash == "" {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"voting has not started yet"},
			}
		}

		// Handle StartVote versioning
		var vdr *www2.VoteDetailsReply
		switch dvdr.StartVote.Version {
		case decredplugin.VersionStartVoteV1:
			b := []byte(dvdr.StartVote.Payload)
			dsv1, err := decredplugin.DecodeStartVoteV1(b)
			if err != nil {
				return nil, err
			}
			vdr, err = convertDecredStartVoteV1ToVoteDetailsReplyV2(*dsv1,
				dvdr.StartVoteReply)
			if err != nil {
				return nil, err
			}
		case decredplugin.VersionStartVoteV2:
			b := []byte(dvdr.StartVote.Payload)
			dsv2, err := decredplugin.DecodeStartVoteV2(b)
			if err != nil {
				return nil, err
			}
			vdr, err = convertDecredStartVoteV2ToVoteDetailsReplyV2(*dsv2,
				dvdr.StartVoteReply)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("invalid StartVote version %v %v",
				token, dvdr.StartVote.Version)
		}

		return vdr, nil
	*/

	return nil, nil
}
