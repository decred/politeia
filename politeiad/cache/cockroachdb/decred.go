// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// decredVersion is the version of the cache implementation of
	// decred plugin. This may differ from the decredplugin package
	// version.
	decredVersion = "1.2"

	// Decred plugin table names
	tableProposalMetadata  = "proposal_metadata"
	tableComments          = "comments"
	tableCommentLikes      = "comment_likes"
	tableCastVotes         = "cast_votes"
	tableAuthorizeVotes    = "authorize_votes"
	tableVoteOptions       = "vote_options"
	tableStartVotes        = "start_votes"
	tableVoteOptionResults = "vote_option_results"
	tableVoteResults       = "vote_results"

	// Vote option IDs
	voteOptionIDApproved = "yes"
)

// decred implements the PluginDriver interface.
type decred struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of decred cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// publicStatuses returns an array of ints that represents all the publicly
// viewable politeiad record statuses. The statuses are returned as ints so
// that they can be inserted into queries.
func publicStatuses() []int {
	return []int{
		int(pd.RecordStatusPublic),
		int(pd.RecordStatusArchived),
	}
}

// authorizeVotes returns a map[token]AuthorizeVote for the given records. An
// entry in the returned map will only exist if an AuthorizeVote is found for
// the record.
func (d *decred) authorizeVotes(records []Record) (map[string]AuthorizeVote, error) {
	authorizeVotes := make(map[string]AuthorizeVote, len(records))

	if len(records) == 0 {
		return authorizeVotes, nil
	}

	keys := make([]string, 0, len(records))
	for _, v := range records {
		keys = append(keys, v.Token+strconv.FormatUint(v.Version, 10))
	}

	avs := make([]AuthorizeVote, 0, len(keys))
	err := d.recordsdb.
		Where("key IN (?)", keys).
		Find(&avs).
		Error
	if err != nil {
		return nil, fmt.Errorf("select AuthorizeVotes in %v: %v",
			keys, err)
	}

	for _, av := range avs {
		authorizeVotes[av.Token] = av
	}

	return authorizeVotes, nil
}

// startVotes returns a map[token]StartVote for the given tokens. An entry in
// the returned map will only exist for tokens where a StartVote was found.
func (d *decred) startVotes(tokens []string) (map[string]StartVote, error) {
	startVotes := make(map[string]StartVote, len(tokens))

	if len(tokens) == 0 {
		return startVotes, nil
	}

	svs := make([]StartVote, 0, len(tokens))
	err := d.recordsdb.
		Where("token IN (?)", tokens).
		Preload("Options").
		Find(&svs).
		Error
	if err != nil {
		return nil, fmt.Errorf("select StartVotes in %v: %v",
			tokens, err)
	}

	for _, v := range svs {
		startVotes[v.Token] = v
	}

	return startVotes, nil
}

// voteOptionResults returns the VoteOptionResult for each of the given
// VoteOptions. The results are looked up manually from the CastVotes table
// instead of using the VoteResults table. This allows results to be looked up
// when a VoteResults entry does not yet exist, such as for ongoing votes.
func (d *decred) voteOptionResults(options []VoteOption) ([]VoteOptionResult, error) {
	results := make([]VoteOptionResult, 0, len(options))

	for _, v := range options {
		var votes uint64
		tokenVoteBit := v.Token + strconv.FormatUint(v.Bits, 16)
		err := d.recordsdb.
			Model(&CastVote{}).
			Where("token_vote_bit = ?", tokenVoteBit).
			Count(&votes).
			Error
		if err != nil {
			return nil, fmt.Errorf("select CastVote count for %v: %v",
				tokenVoteBit, err)
		}

		results = append(results, VoteOptionResult{
			Key:   tokenVoteBit,
			Token: v.Token,
			Votes: votes,
			Option: VoteOption{
				ID:          v.ID,
				Description: v.Description,
				Bits:        v.Bits,
			},
		})
	}

	return results, nil
}

// voteResultsMissing returns the tokens of the standard proposal votes and
// runoff proposal votes that have finished voting but are missing from the
// lazy loaded VoteResults table.
func (d *decred) voteResultsMissing(bestBlock uint64) ([]string, []string, error) {
	// Find standard vote proposals that have finished voting but
	// have not yet been added to the VoteResults table.
	q := `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND start_votes.Type = ?
          AND vote_results.token IS NULL`
	rows, err := d.recordsdb.Raw(q, bestBlock,
		int(decredplugin.VoteTypeStandard)).Rows()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup missing standard vote results: %v",
			err)
	}
	defer rows.Close()

	standard := make([]string, 0, 1024)
	for rows.Next() {
		var token string
		rows.Scan(&token)
		standard = append(standard, token)
	}

	// Find runoff vote proposals that have finished voting but
	// have not yet been added to the VoteResults table.
	q = `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND start_votes.Type = ?
          AND vote_results.token IS NULL`
	rows, err = d.recordsdb.Raw(q, bestBlock,
		int(decredplugin.VoteTypeRunoff)).Rows()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup missing runoff vote results: %v",
			err)
	}
	defer rows.Close()

	runoff := make([]string, 0, 1024)
	for rows.Next() {
		var token string
		rows.Scan(&token)
		runoff = append(runoff, token)
	}

	return standard, runoff, nil
}

// voteResultsCompile compiles the results of a standard vote and returns a
// VoteResults. The vote is considered approved if the quorum and pass
// percentage requirements are met.
func voteResultsCompile(sv StartVote, votes []CastVote) VoteResults {
	// Tally cast votes
	tally := make(map[string]uint64) // [voteBit]voteCount
	for _, v := range votes {
		tally[v.VoteBit]++
	}

	// Prepare vote option results
	results := make([]VoteOptionResult, 0, len(sv.Options))
	for _, v := range sv.Options {
		voteBit := strconv.FormatUint(v.Bits, 16)
		voteCount := tally[voteBit]

		results = append(results, VoteOptionResult{
			Key:    sv.Token + voteBit,
			Votes:  voteCount,
			Option: v,
		})
	}

	// Check whether vote was approved
	var total uint64
	for _, v := range results {
		total += v.Votes
	}

	eligible := len(strings.Split(sv.EligibleTickets, ","))
	quorum := uint64(float64(sv.QuorumPercentage) / 100 * float64(eligible))
	pass := uint64(float64(sv.PassPercentage) / 100 * float64(total))

	// XXX this does not support multiple choice votes yet
	var (
		approvedVotes uint64 // Number of approve votes
		approved      bool   // Is the proposal vote approved
	)
	for _, v := range results {
		if v.Option.ID == decredplugin.VoteOptionIDApprove {
			approvedVotes = v.Votes
		}
	}
	switch {
	case total < quorum:
		// Quorum not met
	case approvedVotes < pass:
		// Pass percentage not met
	default:
		// Vote was approved
		approved = true
	}

	return VoteResults{
		Token:    sv.Token,
		Approved: approved,
		Results:  results,
	}
}

// voteResultsInsertStandard calculates the vote results for a standard
// proposal vote and inserts a VoteResults record into the cache. A VoteResults
// record should only be created for proposals once the voting period has
// ended.
func (d *decred) voteResultsInsertStandard(token string) error {
	log.Tracef("insertVoteResults %v", token)

	// Lookup start vote
	var sv StartVote
	err := d.recordsdb.
		Where("token = ?", token).
		Preload("Options").
		Find(&sv).
		Error
	if err != nil {
		return fmt.Errorf("lookup start vote %v: %v",
			token, err)
	}

	// Lookup cast votes
	var cv []CastVote
	err = d.recordsdb.
		Where("token = ?", token).
		Find(&cv).
		Error
	if err == gorm.ErrRecordNotFound {
		// No cast votes exists. In theory, this could
		// happen if no one were to vote on a proposal.
		// In practice, this shouldn't happen.
	} else if err != nil {
		return fmt.Errorf("lookup cast votes: %v", err)
	}

	// Create a vote results entry
	vr := voteResultsCompile(sv, cv)
	err = d.recordsdb.Create(&vr).Error
	if err != nil {
		return fmt.Errorf("insert vote results: %v", err)
	}

	return nil
}

// voteResultsInsertRunoff calculates the results of a runoff vote and inserts
// a VoteResults record into the cache for each of the runoff vote submissions.
func (d *decred) voteResultsInsertRunoff(rfpToken string) error {
	log.Tracef("voteResultsInsertRunoffVote: %v", rfpToken)

	linkedFrom, err := d.linkedFrom(rfpToken)
	if err != nil {
		return err
	}

	// Compile vote results for all RFP submissions
	results := make([]VoteResults, 0, len(linkedFrom))
	for _, token := range linkedFrom {
		// Make sure record hasn't been abandoned
		var r Record
		err = d.recordsdb.
			Where("records.token = ?", token).
			Order("records.version desc").
			Limit(1).
			Preload("Metadata").
			Find(&r).
			Error
		if err != nil {
			return fmt.Errorf("lookup record %v: %v",
				token, err)
		}
		if r.Status == int(pd.RecordStatusArchived) {
			// RFP submission has been abandoned
			continue
		}

		// Lookup start vote
		var sv StartVote
		err := d.recordsdb.
			Where("token = ?", token).
			Preload("Options").
			Find(&sv).
			Error
		if err != nil {
			return fmt.Errorf("find start vote %v: %v",
				token, err)
		}

		// Lookup cast votes
		var cv []CastVote
		err = d.recordsdb.
			Where("token = ?", token).
			Find(&cv).
			Error
		if err == gorm.ErrRecordNotFound {
			// No cast votes exists. In theory, this could
			// happen if no one were to vote on a proposal.
			// In practice, this shouldn't happen.
		} else if err != nil {
			return fmt.Errorf("lookup cast votes: %v", err)
		}

		// Compile vote results. This will mark the vote as
		// approved if it meets the specified quorum and pass
		// requirements. The actual runoff vote winner is
		// determined later in this function.
		results = append(results, voteResultsCompile(sv, cv))
	}

	// Determine runoff vote winner. The winner is the vote
	// that passed the quorum and pass requirments and has
	// the most net approved votes.
	var (
		winnerNetApprove int    // Net number of approve votes of the winner
		winnerToken      string // Censorship token of the winner
	)
	for _, vr := range results {
		if !vr.Approved {
			// Vote did not meet quorum and pass requirements
			continue
		}

		// Check if this proposal has more net approved votes
		// then the current highest.
		var (
			votesApprove uint64 // Number of approve votes
			votesReject  uint64 // Number of reject votes
		)
		for _, vor := range vr.Results {
			switch vor.Option.ID {
			case decredplugin.VoteOptionIDApprove:
				votesApprove = vor.Votes
			case decredplugin.VoteOptionIDReject:
				votesReject = vor.Votes
			default:
				// Runoff vote options can only be approve/reject
				return fmt.Errorf("unknown runoff vote option %v %v",
					vr.Token, vor.Option.ID)
			}

			netApprove := int(votesApprove) - int(votesReject)
			if netApprove > winnerNetApprove {
				// New winner!
				winnerToken = vr.Token
				winnerNetApprove = netApprove
			}

			// This doesn't handle the unlikely case that the
			// runoff vote results in a tie. If that happens
			// we can decide how to handle it and rebuild the
			// cache with the new rules.
		}
	}

	// Now that we know the winner we can update the losers
	// and insert the results into the cache.
	for _, vr := range results {
		// Update runoff vote losers
		if vr.Token != winnerToken {
			vr.Approved = false
		}

		// Insert vote results record
		err = d.recordsdb.Create(&vr).Error
		if err != nil {
			return fmt.Errorf("insert vote results %v: %v",
				vr.Token, err)
		}
	}

	return nil
}

func (d *decred) voteResultsLoad(bestBlock uint64) error {
	standard, runoff, err := d.voteResultsMissing(bestBlock)
	if err != nil {
		return err
	}

	// Insert vote results for standard votes proposals.
	for _, token := range standard {
		err := d.voteResultsInsertStandard(token)
		if err != nil {
			return fmt.Errorf("voteResultsInsertStandard %v: %v",
				token, err)
		}
	}

	// Insert vote results for the runoff vote submissions. Runoff
	// votes are identitified by the parent RFP proposal token.
	done := make(map[string]struct{}, len(runoff)) // [rfpToken]struct{}
	for _, token := range runoff {
		// Lookup the RFP token for the runoff vote submission
		var pm ProposalMetadata
		err := d.recordsdb.
			Where("token = ?", token).
			Find(&pm).
			Error
		if err != nil {
			return fmt.Errorf("lookup ProposalMetadata %v: %v",
				token, err)
		}
		if pm.LinkTo == "" {
			return fmt.Errorf("runoff vote linkto not found %v",
				token)
		}

		if _, ok := done[pm.LinkTo]; ok {
			// Results have already been inserted for this RFP.
			// This happens because the vote results are built
			// using the RFP token and all RFP submissions will
			// list the same RFP token in their LinkTo field.
			continue
		}

		// Insert vote results for the full runoff vote
		err = d.voteResultsInsertRunoff(pm.LinkTo)
		if err != nil {
			return fmt.Errorf("insert runoff vote results %v: %v",
				pm.LinkTo, err)
		}

		done[pm.LinkTo] = struct{}{}
	}

	return nil
}

// voteResults returns a map[token]VoteResults for the given tokens.
//
// The VoteResults table is lazy loaded. A cache.ErrRecordNotFound error is
// returned if the VoteResults table is not up-to-date.
func (d *decred) voteResults(tokens []string, bestBlock uint64) (map[string]VoteResults, error) {
	// Check to see if the VoteResults table needs to be updated
	standard, runoff, err := d.voteResultsMissing(bestBlock)
	if err != nil {
		return nil, err
	}
	if len(standard) > 0 || len(runoff) > 0 {
		// Return a ErrRecordNotFound to indicate one
		// or more vote result records were not found.
		return nil, cache.ErrRecordNotFound
	}

	voteResults := make(map[string]VoteResults, len(tokens))
	if len(tokens) == 0 {
		return voteResults, nil
	}

	// Lookup vote results
	vrs := make([]VoteResults, 0, len(tokens))
	err = d.recordsdb.
		Where("token IN (?)", tokens).
		Preload("Results").
		Preload("Results.Option").
		Find(&vrs).
		Error
	if err != nil {
		return nil, fmt.Errorf("select VoteResults in %v: %v",
			tokens, err)
	}

	for _, v := range vrs {
		voteResults[v.Token] = v
	}

	return voteResults, nil
}

// voteSummaries returns a map[string]decredplugin.VoteSummaryReply for the
// given proposal tokens. An entry in the returned map will only exist for
// tokens where a Record was found.
//
// This function pulls data from the the lazy loaded VoteResults table. A
// cache.ErrRecordNotFound error is returned if the VoteResults table is not
// up-to-date.
func (d *decred) voteSummaries(tokens []string, bestBlock uint64) (map[string]decredplugin.VoteSummaryReply, error) {
	// This query returns the latest version of the given records.
	query := `SELECT a.* 
            FROM records a
            LEFT OUTER JOIN records b
              ON a.token = b.token 
              AND a.version < b.version
              WHERE b.token IS NULL 
              AND a.token IN (?)`
	rows, err := d.recordsdb.Raw(query, tokens).Rows()
	if err != nil {
		return nil, fmt.Errorf("select records %v: %v",
			tokens, err)
	}
	defer rows.Close()

	records := make([]Record, 0, len(tokens))
	for rows.Next() {
		var r Record
		err := d.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Lookup the AuthorizeVote for each record
	authVotes, err := d.authorizeVotes(records)
	if err != nil {
		return nil, fmt.Errorf("authorizeVotes: %v", err)
	}

	// Lookup the StartVote for each record that has an AuthorizeVote
	tokens = make([]string, 0, len(authVotes))
	for token := range authVotes {
		tokens = append(tokens, token)
	}
	startVotes, err := d.startVotes(tokens)
	if err != nil {
		return nil, fmt.Errorf("startVotes: %v", err)
	}

	// Lookup the VoteResults for each record that has a StartVote
	tokens = make([]string, 0, len(startVotes))
	for token := range startVotes {
		tokens = append(tokens, token)
	}

	// Check for missing vote results tables
	voteResults, err := d.voteResults(tokens, bestBlock)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			// The VoteResults table needs to be updated. Return
			// just the error so the calling function can key off
			// of it.
			return nil, err
		}
		return nil, fmt.Errorf("voteResults: %v", err)
	}

	if len(tokens) != len(voteResults) {
		// There were tokens that do not correspond to a VoteResults
		// entry. This happens when the proposal vote has either not
		// begun or is ongoing. We know that these tokens have a
		// StartVote so the vote must be ongoing. Lookup the results
		// manually.
		for _, token := range tokens {
			_, ok := voteResults[token]
			if !ok {
				sv := startVotes[token]
				results, err := d.voteOptionResults(sv.Options)
				if err != nil {
					return nil, fmt.Errorf("voteOptionResults %v: %v",
						sv.Token, err)
				}
				voteResults[token] = VoteResults{
					Token:    token,
					Approved: false,
					Results:  results,
				}
			}
		}
	}

	// Prepare vote summaries
	summaries := make(map[string]decredplugin.VoteSummaryReply, len(records))
	for _, v := range records {
		av := authVotes[v.Token]
		sv := startVotes[v.Token]
		vr := voteResults[v.Token]

		// Return "" not "0" if end height doesn't exist
		var endHeight string
		if sv.EndHeight != 0 {
			endHeight = strconv.FormatUint(uint64(sv.EndHeight), 10)
		}

		summaries[v.Token] = decredplugin.VoteSummaryReply{
			Authorized:          av.Action == decredplugin.AuthVoteActionAuthorize,
			Type:                decredplugin.VoteT(sv.Type),
			Duration:            sv.Duration,
			EndHeight:           endHeight,
			EligibleTicketCount: sv.EligibleTicketCount,
			QuorumPercentage:    sv.QuorumPercentage,
			PassPercentage:      sv.PassPercentage,
			Results:             convertVoteOptionResultsToDecred(vr.Results),
			Approved:            vr.Approved,
		}
	}

	return summaries, nil
}

// cmdNewComment creates a Comment record using the passed in payloads and
// inserts it into the database.
func (d *decred) cmdNewComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdNewComment")

	nc, err := decredplugin.DecodeNewComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	ncr, err := decredplugin.DecodeNewCommentReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	c := convertNewCommentFromDecred(*nc, *ncr)
	err = d.recordsdb.Create(&c).Error

	return replyPayload, err
}

// cmdLikeComment creates a LikeComment record using the passed in payloads
// and inserts it into the database.
func (d *decred) cmdLikeComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdLikeComment")

	dlc, err := decredplugin.DecodeLikeComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	lc := convertLikeCommentFromDecred(*dlc)
	err = d.recordsdb.Create(&lc).Error

	return replyPayload, err
}

// cmdCensorComment censors an existing comment.  A censored comment has its
// comment message removed and is marked as censored.
func (d *decred) cmdCensorComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdCensorComment")

	cc, err := decredplugin.DecodeCensorComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	c := Comment{
		Key: cc.Token + cc.CommentID,
	}
	err = d.recordsdb.Model(&c).
		Updates(map[string]interface{}{
			"comment":  "",
			"censored": true,
		}).Error

	return replyPayload, err
}

func (d *decred) commentGetByID(token string, commentID string) (*Comment, error) {
	c := Comment{
		Key: token + commentID,
	}
	err := d.recordsdb.Find(&c).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (d *decred) commentGetBySignature(token string, sig string) (*Comment, error) {
	var c Comment
	err := d.recordsdb.
		Where("token = ? AND signature = ?", token, sig).
		Find(&c).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return nil, err
	}
	return &c, nil
}

// cmdGetComment retreives the passed in comment from the database.
func (d *decred) cmdGetComment(payload string) (string, error) {
	log.Tracef("decred cmdGetComment")

	gc, err := decredplugin.DecodeGetComment([]byte(payload))
	if err != nil {
		return "", err
	}

	if gc.Token == "" {
		return "", cache.ErrInvalidPluginCmdArgs
	}

	var c *Comment
	switch {
	case gc.CommentID != "":
		c, err = d.commentGetByID(gc.Token, gc.CommentID)
	case gc.Signature != "":
		c, err = d.commentGetBySignature(gc.Token, gc.Signature)
	default:
		return "", cache.ErrInvalidPluginCmdArgs
	}
	if err != nil {
		return "", err
	}

	gcr := decredplugin.GetCommentReply{
		Comment: convertCommentToDecred(*c),
	}
	gcrb, err := decredplugin.EncodeGetCommentReply(gcr)
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

// cmdGetComments returns all of the comments for the passed in record token.
func (d *decred) cmdGetComments(payload string) (string, error) {
	log.Tracef("decred cmdGetComments")

	gc, err := decredplugin.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", err
	}

	comments := make([]Comment, 0, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ?", gc.Token).
		Find(&comments).
		Error
	if err != nil {
		return "", err
	}

	dpc := make([]decredplugin.Comment, 0, len(comments))
	for _, c := range comments {
		dpc = append(dpc, convertCommentToDecred(c))
	}

	gcr := decredplugin.GetCommentsReply{
		Comments: dpc,
	}
	gcrb, err := decredplugin.EncodeGetCommentsReply(gcr)
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

// cmdGetNumComments returns an encoded plugin reply that contains a
// [token]numComments map for the provided list of censorship tokens. If a
// provided token does not correspond to an actual proposal then it will not
// be included in the returned map.
func (d *decred) cmdGetNumComments(payload string) (string, error) {
	log.Tracef("decred cmdGetNumComments")

	gnc, err := decredplugin.DecodeGetNumComments([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup number of comments for provided tokens
	type Result struct {
		Token  string
		Counts int
	}
	results := make([]Result, 0, len(gnc.Tokens))
	err = d.recordsdb.
		Table("comments").
		Select("count(*) as counts, token").
		Group("token").
		Where("token IN (?)", gnc.Tokens).
		Find(&results).
		Error
	if err != nil {
		return "", err
	}

	// Put results into a map
	numComments := make(map[string]int, len(results)) // [token]numComments
	for _, c := range results {
		numComments[c.Token] = c.Counts
	}

	// Encode reply
	gncr := decredplugin.GetNumCommentsReply{
		NumComments: numComments,
	}
	gncre, err := decredplugin.EncodeGetNumCommentsReply(gncr)
	if err != nil {
		return "", err
	}

	return string(gncre), nil
}

// cmdCommentLikes returns all of the comment likes for the passed in comment.
func (d *decred) cmdCommentLikes(payload string) (string, error) {
	log.Tracef("decred cmdCommentLikes")

	cl, err := decredplugin.DecodeCommentLikes([]byte(payload))
	if err != nil {
		return "", err
	}

	likes := make([]LikeComment, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ? AND comment_id = ?", cl.Token, cl.CommentID).
		Find(&likes).
		Error
	if err != nil {
		return "", err
	}

	lc := make([]decredplugin.LikeComment, 0, len(likes))
	for _, v := range likes {
		lc = append(lc, convertLikeCommentToDecred(v))
	}

	clr := decredplugin.CommentLikesReply{
		CommentLikes: lc,
	}
	clrb, err := decredplugin.EncodeCommentLikesReply(clr)
	if err != nil {
		return "", err
	}

	return string(clrb), nil
}

// cmdProposalLikes returns all of the comment likes for all comments of the
// passed in record token.
func (d *decred) cmdProposalCommentsLikes(payload string) (string, error) {
	log.Tracef("decred cmdProposalCommentsLikes")

	cl, err := decredplugin.DecodeGetProposalCommentsLikes([]byte(payload))
	if err != nil {
		return "", err
	}

	likes := make([]LikeComment, 0, 1024) // PNOOMA
	err = d.recordsdb.
		Where("token = ?", cl.Token).
		Find(&likes).
		Error
	if err != nil {
		return "", err
	}

	lc := make([]decredplugin.LikeComment, 0, len(likes))
	for _, v := range likes {
		lc = append(lc, convertLikeCommentToDecred(v))
	}

	clr := decredplugin.GetProposalCommentsLikesReply{
		CommentsLikes: lc,
	}
	clrb, err := decredplugin.EncodeGetProposalCommentsLikesReply(clr)
	if err != nil {
		return "", err
	}

	return string(clrb), nil
}

// authorizeVoteInsert creates an AuthorizeVote record and inserts it into the
// database. If a previous AuthorizeVote record exists for the passed in
// proposal and version, it will be deleted before the new AuthorizeVote record
// is inserted.
//
// This function must be called using a transaction.
func authorizeVoteInsert(tx *gorm.DB, av AuthorizeVote) error {
	// Delete authorize vote if one exists for this version
	err := tx.Where("key = ?", av.Key).
		Delete(AuthorizeVote{}).
		Error
	if err != nil {
		return fmt.Errorf("delete authorize vote: %v", err)
	}

	// Add new authorize vote
	err = tx.Create(&av).Error
	if err != nil {
		return fmt.Errorf("create authorize vote: %v", err)
	}

	return nil
}

// cmdAuthorizeVote creates a AuthorizeVote record using the passed in payloads
// and inserts it into the database.
func (d *decred) cmdAuthorizeVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdAuthorizeVote")

	av, err := decredplugin.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}
	a, err := convertAuthorizeVoteFromDecred(*av, *avr)
	if err != nil {
		return "", err
	}

	// Run update in a transaction
	tx := d.recordsdb.Begin()
	err = authorizeVoteInsert(tx, *a)
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("authorizeVoteInsert: %v", err)
	}

	// Commit transaction
	err = tx.Commit().Error
	if err != nil {
		return "", fmt.Errorf("commit transaction: %v", err)
	}

	return replyPayload, nil
}

// startVoteInsert inserts a StartVote record into the database. This function
// has a database parameter so that it can be called inside of a transaction
// when required.
func startVoteInsert(db *gorm.DB, sv StartVote) error {
	return db.Create(&sv).Error
}

// cmdStartVote creates a StartVote record using the passed in payloads and
// inserts it into the database.
func (d *decred) cmdStartVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdStartVote")

	sv, err := decredplugin.DecodeStartVoteV2([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	err = sv.VerifySignature()
	if err != nil {
		return "", fmt.Errorf("verify signature: %v", err)
	}
	svr, err := decredplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}
	s, err := convertStartVoteV2FromDecred(*sv, *svr)
	if err != nil {
		return "", err
	}

	err = startVoteInsert(d.recordsdb, *s)
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

func (d *decred) cmdStartVoteRunoff(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdStartVoteRunoff")

	sv, err := decredplugin.DecodeStartVoteRunoff([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := decredplugin.DecodeStartVoteRunoffReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// Prepare records to be inserted
	authVotes := make([]AuthorizeVote, 0, len(sv.AuthorizeVotes))
	for _, v := range sv.AuthorizeVotes {
		avr := svr.AuthorizeVoteReplies[v.Token]
		a, err := convertAuthorizeVoteFromDecred(v, avr)
		if err != nil {
			return "", err
		}
		authVotes = append(authVotes, *a)
	}
	startVotes := make([]StartVote, 0, len(sv.StartVotes))
	for _, v := range sv.StartVotes {
		s, err := convertStartVoteV2FromDecred(v, svr.StartVoteReply)
		if err != nil {
			return "", err
		}
		startVotes = append(startVotes, *s)
	}

	// Run updates in a transaction
	tx := d.recordsdb.Begin()
	for _, v := range authVotes {
		err = authorizeVoteInsert(tx, v)
		if err != nil {
			tx.Rollback()
			return "", err
		}
	}
	for _, v := range startVotes {
		err := startVoteInsert(tx, v)
		if err != nil {
			tx.Rollback()
			return "", err
		}
	}
	err = tx.Commit().Error
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

// cmdVoteDetails returns the AuthorizeVote and StartVote records for the
// passed in record token.
func (d *decred) cmdVoteDetails(payload string) (string, error) {
	log.Tracef("decred cmdVoteDetails")

	vd, err := decredplugin.DecodeVoteDetails([]byte(payload))
	if err != nil {
		return "", nil
	}

	// Lookup the most recent version of the record
	var r Record
	err = d.recordsdb.
		Where("records.token = ?", vd.Token).
		Order("records.version desc").
		Limit(1).
		Find(&r).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	// Lookup authorize vote
	var av AuthorizeVote
	key := vd.Token + strconv.FormatUint(r.Version, 10)
	err = d.recordsdb.
		Where("key = ?", key).
		Find(&av).
		Error
	if err == gorm.ErrRecordNotFound {
		// An authorize vote may note exist. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("authorize vote lookup failed: %v", err)
	}

	// Lookup start vote
	var (
		sv   StartVote
		dsv  decredplugin.StartVote
		dsvr decredplugin.StartVoteReply
	)
	err = d.recordsdb.
		Where("token = ?", vd.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// A start vote may note exist. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("start vote lookup failed: %v", err)
	}

	// Only convert if a StartVote was found, otherwise it will
	// throw an invalid version error.
	if sv.Version != 0 {
		dsvp, dsvrp, err := convertStartVoteToDecred(sv)
		if err != nil {
			return "", err
		}
		dsv = *dsvp
		dsvr = *dsvrp
	}

	// Prepare reply
	vdr := decredplugin.VoteDetailsReply{
		AuthorizeVote:  convertAuthorizeVoteToDecred(av),
		StartVote:      dsv,
		StartVoteReply: dsvr,
	}
	vdrb, err := decredplugin.EncodeVoteDetailsReply(vdr)
	if err != nil {
		return "", err
	}

	return string(vdrb), nil
}

// cmdNewBallot creates CastVote records using the passed in payloads and
// inserts them into the database.
func (d *decred) cmdNewBallot(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdNewBallot")

	b, err := decredplugin.DecodeBallot([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	br, err := decredplugin.DecodeBallotReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// Put votes receipts into a map for easy lookup. Only votes
	// with a receipt signature will be added to the cache.
	receipts := make(map[string]string, len(br.Receipts)) // [clientSig]receiptSig
	for _, v := range br.Receipts {
		receipts[v.ClientSignature] = v.Signature
	}

	// Add cast votes to the cache
	for _, v := range b.Votes {
		// Don't add votes that don't have a receipt signature
		if receipts[v.Signature] == "" {
			log.Debugf("cmdNewBallot: vote receipt not found %v %v",
				v.Token, v.Ticket)
			continue
		}

		cv := convertCastVoteFromDecred(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			return "", err
		}
	}

	return replyPayload, nil
}

// cmdProposalVotes returns the StartVote record and all CastVote records for
// the passed in record token.
func (d *decred) cmdProposalVotes(payload string) (string, error) {
	log.Tracef("decred cmdProposalVotes")

	vr, err := decredplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup all cast votes
	var cv []CastVote
	err = d.recordsdb.
		Where("token = ?", vr.Token).
		Find(&cv).
		Error
	if err == gorm.ErrRecordNotFound {
		// No cast votes may exist yet. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("cast votes lookup failed: %v", err)
	}

	// Prepare reply
	dcv := make([]decredplugin.CastVote, 0, len(cv))
	for _, v := range cv {
		dcv = append(dcv, convertCastVoteToDecred(v))
	}

	vrr := decredplugin.VoteResultsReply{
		CastVotes: dcv,
	}

	vrrb, err := decredplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", err
	}

	return string(vrrb), nil
}

// cmdInventory returns the decred plugin inventory.
func (d *decred) cmdInventory() (string, error) {
	log.Tracef("decred cmdInventory")

	// XXX the only part of the decred plugin inventory that we return
	// at the moment is comments. This is because comments are the only
	// thing politeiawww currently needs on startup.

	// Get all comments
	var c []Comment
	err := d.recordsdb.Find(&c).Error
	if err != nil {
		return "", err
	}

	dc := make([]decredplugin.Comment, 0, len(c))
	for _, v := range c {
		dc = append(dc, convertCommentToDecred(v))
	}

	// Prepare inventory reply
	ir := decredplugin.InventoryReply{
		Comments: dc,
	}
	irb, err := decredplugin.EncodeInventoryReply(ir)
	if err != nil {
		return "", err
	}

	return string(irb), err
}

// cmdLoadVoteResults creates vote results entries for any proposals that have
// a finished voting period but have not yet been added to the vote results
// table. The vote results table is lazy loaded.
func (d *decred) cmdLoadVoteResults(payload string) (string, error) {
	log.Tracef("cmdLoadVoteResults")

	lvs, err := decredplugin.DecodeLoadVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	err = d.voteResultsLoad(lvs.BestBlock)
	if err != nil {
		return "", err
	}

	r := decredplugin.LoadVoteResultsReply{}
	reply, err := decredplugin.EncodeLoadVoteResultsReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdTokenInventory returns the tokens of all records in the cache,
// categorized by stage of the voting process. This call relies on the lazy
// loaded VoteResults table. A cache.ErrRecordNotFound is returned if the
// VoteResults table is not up-to-date.
func (d *decred) cmdTokenInventory(payload string) (string, error) {
	log.Tracef("decred cmdTokenInventory")

	ti, err := decredplugin.DecodeTokenInventory([]byte(payload))
	if err != nil {
		return "", err
	}

	// The VoteResults table is lazy loaded. Check to see if it
	// needs to be updated.
	standard, runoff, err := d.voteResultsMissing(ti.BestBlock)
	if err != nil {
		return "", err
	}
	if len(standard) > 0 || len(runoff) > 0 {
		// Return a ErrRecordNotFound to indicate one
		// or more vote result records were not found.
		return "", cache.ErrRecordNotFound
	}

	// Pre voting period tokens. This query returns the
	// tokens of the most recent version of all records that
	// are public and do not have an associated StartVote
	// record, ordered by timestamp in descending order.
	q := `SELECT a.token
        FROM records a
        LEFT OUTER JOIN start_votes
          ON a.token = start_votes.token
        LEFT OUTER JOIN records b
          ON a.token = b.token
          AND a.version < b.version
        WHERE b.token IS NULL
          AND start_votes.token IS NULL
          AND a.status = ?
        ORDER BY a.timestamp DESC`
	rows, err := d.recordsdb.Raw(q, pd.RecordStatusPublic).Rows()
	if err != nil {
		return "", fmt.Errorf("pre: %v", err)
	}
	defer rows.Close()

	var token string
	pre := make([]string, 0, 1024)
	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		pre = append(pre, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Active voting period tokens
	q = `SELECT token
       FROM start_votes
       WHERE end_height > ?
       ORDER BY end_height DESC`
	rows, err = d.recordsdb.Raw(q, ti.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("active: %v", err)
	}
	defer rows.Close()

	active := make([]string, 0, 1024)
	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		active = append(active, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Approved vote tokens
	q = `SELECT vote_results.token
       FROM vote_results
       INNER JOIN start_votes
         ON vote_results.token = start_votes.token
         WHERE vote_results.approved = true
       ORDER BY start_votes.end_height DESC`
	rows, err = d.recordsdb.Raw(q).Rows()
	if err != nil {
		return "", fmt.Errorf("approved: %v", err)
	}
	defer rows.Close()

	approved := make([]string, 0, 1024)
	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		approved = append(approved, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Rejected vote tokens
	q = `SELECT vote_results.token
       FROM vote_results
       INNER JOIN start_votes
         ON vote_results.token = start_votes.token
         WHERE vote_results.approved = false
       ORDER BY start_votes.end_height DESC`
	rows, err = d.recordsdb.Raw(q).Rows()
	if err != nil {
		return "", fmt.Errorf("rejected: %v", err)
	}
	defer rows.Close()

	rejected := make([]string, 0, 1024)
	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		rejected = append(rejected, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Abandoned tokens
	abandoned := make([]string, 0, 1024)
	q = `SELECT token
       FROM records
       WHERE status = ?
       ORDER BY timestamp DESC`
	rows, err = d.recordsdb.Raw(q, pd.RecordStatusArchived).Rows()
	if err != nil {
		return "", fmt.Errorf("abandoned: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		abandoned = append(abandoned, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Setup reply
	tir := decredplugin.TokenInventoryReply{
		Pre:        pre,
		Active:     active,
		Approved:   approved,
		Rejected:   rejected,
		Abandoned:  abandoned,
		Unreviewed: []string{},
		Censored:   []string{},
	}

	// Populate unvetted records if specified
	if ti.Unvetted {
		// Unreviewed tokens. Edits to an unreviewed record do not
		// increment the version. Only edits to a public record
		// increment the version. This means means we don't need
		// to worry about fetching the most recent version here
		// because an unreviewed record will only have one version.
		unreviewed := make([]string, 0, 1024)
		q = `SELECT token
         FROM records
         WHERE status = ? or status = ?
         ORDER BY timestamp DESC`
		rows, err = d.recordsdb.Raw(q, pd.RecordStatusNotReviewed,
			pd.RecordStatusUnreviewedChanges).Rows()
		if err != nil {
			return "", fmt.Errorf("unreviewed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			err = rows.Scan(&token)
			if err != nil {
				return "", err
			}
			unreviewed = append(unreviewed, token)
		}
		if err = rows.Err(); err != nil {
			return "", err
		}
		// Censored tokens
		censored := make([]string, 0, 1024)
		q = `SELECT token
         FROM records
         WHERE status = ?
         ORDER BY timestamp DESC`
		rows, err = d.recordsdb.Raw(q, pd.RecordStatusCensored).Rows()
		if err != nil {
			return "", fmt.Errorf("censored: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			err = rows.Scan(&token)
			if err != nil {
				return "", err
			}
			censored = append(censored, token)
		}
		if err = rows.Err(); err != nil {
			return "", err
		}

		// Update reply
		tir.Unreviewed = unreviewed
		tir.Censored = censored
	}

	// Encode reply
	reply, err := decredplugin.EncodeTokenInventoryReply(tir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdVoteSummary returns a map[string]VoteSummaryReply for the given proposal
// tokens. Results are returned for all tokens that correspond to a proposal.
// This includes both unvetted and vetted proposals. Tokens that do no
// correspond to a proposal are not included in the returned map.
//
// This function pulls data from the the lazy loaded VoteResults table. A
// cache.ErrRecordNotFound error is returned if the VoteResults table is not
// up-to-date.
func (d *decred) cmdBatchVoteSummary(payload string) (string, error) {
	log.Tracef("cmdBatchVoteSummary")

	bvs, err := decredplugin.DecodeBatchVoteSummary([]byte(payload))
	if err != nil {
		return "", err
	}

	summaries, err := d.voteSummaries(bvs.Tokens, bvs.BestBlock)
	if err != nil {
		return "", err
	}

	bvsr := decredplugin.BatchVoteSummaryReply{
		Summaries: summaries,
	}
	reply, err := decredplugin.EncodeBatchVoteSummaryReply(bvsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdVoteSummary returns a decredplugin.VoteSummaryReply for the given
// proposal token.
//
// This function pulls data from the the lazy loaded VoteResults table. A
// cache.ErrRecordNotFound error is returned if the VoteResults table is not
// up-to-date.
func (d *decred) cmdVoteSummary(payload string) (string, error) {
	log.Tracef("cmdVoteSummary")

	vs, err := decredplugin.DecodeVoteSummary([]byte(payload))
	if err != nil {
		return "", err
	}

	summaries, err := d.voteSummaries([]string{vs.Token}, vs.BestBlock)
	if err != nil {
		return "", err
	}

	vsr := summaries[vs.Token]
	reply, err := decredplugin.EncodeVoteSummaryReply(vsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// linkedFrom returns the proposal tokens of all publicly viewable proposals
// that have linked to the given proposal token. If the provided token does not
// correspond to an actual proposal record then a nil value is returned instead
// of a []string.
func (d *decred) linkedFrom(token string) ([]string, error) {
	// Ensure the token corresponds to an actual record
	ok, err := recordExists(d.recordsdb, token, "1")
	if err != nil {
		return nil, err
	}
	if !ok {
		// Token doesn't correspond to an actual record
		return nil, nil
	}

	// This query returns the proposals that are publicly viewable,
	// have linked to the provided token, and are the most recent
	// version of their proposal.
	q := `SELECT a.token
        FROM records a
        LEFT OUTER JOIN records b
          ON a.token = b.token
          AND a.version < b.version
        INNER JOIN proposal_metadata
          ON a.token = proposal_metadata.token
        WHERE b.token IS NULL
        AND proposal_metadata.link_to = ?
        AND a.status IN (?)`
	rows, err := d.recordsdb.
		Raw(q, token, publicStatuses()).
		Rows()
	if err != nil {
		return nil, fmt.Errorf("lookup linked from %v: %v", token, err)
	}
	defer rows.Close()

	linkedFrom := make([]string, 0, 256)
	for rows.Next() {
		var token string
		rows.Scan(&token)
		linkedFrom = append(linkedFrom, token)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return linkedFrom, nil
}

func (d *decred) cmdLinkedFrom(payload string) (string, error) {
	log.Tracef("cmdLinkedFrom")

	lf, err := decredplugin.DecodeLinkedFrom([]byte(payload))
	if err != nil {
		return "", err
	}

	linkedFrom := make(map[string][]string, len(lf.Tokens)) // [token]linkedFrom
	for _, token := range lf.Tokens {
		lf, err := d.linkedFrom(token)
		if err != nil {
			return "", err
		}
		if lf == nil {
			// Token doesn't correspond to an actual record. Don't include
			// it in the reply.
			continue
		}
		linkedFrom[token] = lf
	}

	lfr := decredplugin.LinkedFromReply{
		LinkedFrom: linkedFrom,
	}
	reply, err := decredplugin.EncodeLinkedFromReply(lfr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func proposalMetadataNew(r Record) (*ProposalMetadata, error) {
	var name string
	for _, v := range r.Metadata {
		switch v.ID {
		case mdstream.IDProposalGeneral:
			// Pull the name out of the mdstream
			b := []byte(v.Payload)
			version, err := mdstream.DecodeVersion(b)
			if err != nil {
				return nil, err
			}
			switch version {
			case 1:
				pg, err := mdstream.DecodeProposalGeneralV1(b)
				if err != nil {
					return nil, err
				}
				name = pg.Name
			case 2:
				// The proposal name was removed from the ProposalGeneralV2
				// mdtream and added to the ProposalMetadata file.
			}
		}
	}

	// Parse the ProposalMetadata from the proposal files. One will
	// exists for all new proposals but may not exists for older
	// proposals.
	var pm ProposalMetadata
	for _, f := range r.Files {
		switch f.Name {
		case mdstream.FilenameProposalMetadata:
			b, err := base64.StdEncoding.DecodeString(f.Payload)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return nil, err
			}
			name = pm.Name
		}
	}

	return &ProposalMetadata{
		Token:  r.Token,
		Name:   name,
		LinkTo: pm.LinkTo,
		LinkBy: pm.LinkBy,
	}, nil
}

// hookPostNewRecord executes the decred plugin post new record hook. This
// includes inserting a ProposalMetadata record for the given proposal.
//
// This function must be called using a transaction.
func (d *decred) hookPostNewRecord(tx *gorm.DB, payload string) error {
	var r Record
	err := json.Unmarshal([]byte(payload), &r)
	if err != nil {
		return err
	}
	pm, err := proposalMetadataNew(r)
	if err != nil {
		return err
	}
	if pm.Name == "" {
		// XXX Commented out as a temporary workaround for CMS using decred
		// plugin. This needs to be fixed once the plugin architecture is
		// sorted out.
		//
		// return fmt.Errorf("proposal user metadata not found")

		return nil
	}

	// All prososal versions are stored in the cache which means that
	// this new proposal request could be for a brand new proposal or
	// it could be for a new proposal version that is the result of a
	// proposal edit. We only need to store the ProposalMetadata for
	// the most recent version of the proposal. Delete any existing
	// metadata.
	err = tx.Delete(ProposalMetadata{
		Token: r.Token,
	}).Error
	if err != nil {
		return fmt.Errorf("delete: %v", err)
	}

	// Insert new metadata
	err = tx.Create(pm).Error
	if err != nil {
		return fmt.Errorf("create: %v", err)
	}

	return nil
}

// hookPostUpdateRecord executes the decred plugin post update record hook.
// This includes updating the ProposalMetadata in the cache for the given
// proposal. The existing metadata is first deleted before the new metadata is
// inserted.
//
// This function must be called using a transaction.
func (d *decred) hookPostUpdateRecord(tx *gorm.DB, payload string) error {
	var r Record
	err := json.Unmarshal([]byte(payload), &r)
	if err != nil {
		return err
	}
	pm, err := proposalMetadataNew(r)
	if err != nil {
		return err
	}
	if pm.Name == "" {
		// XXX Commented out as a temporary workaround for CMS using decred
		// plugin. This needs to be fixed once the plugin architecture is
		// sorted out.
		//
		// return fmt.Errorf("proposal user metadata not found")

		return nil
	}

	// All prososal versions are stored in the cache which means that
	// this new proposal request could be for a brand new proposal or
	// it could be for a new proposal version that is the result of a
	// proposal edit. We only need to store the ProposalMetadata for
	// the most recent version of the proposal. Delete any existing
	// metadata.
	err = tx.Delete(ProposalMetadata{
		Token: r.Token,
	}).Error
	if err != nil {
		return fmt.Errorf("delete: %v", err)
	}

	// Insert new metadata
	err = tx.Create(pm).Error
	if err != nil {
		return fmt.Errorf("create: %v", err)
	}

	return nil
}

// hookPostUpdateRecordMetadata executes the decred plugin post update record
// metadata hook.
func (d *decred) hookPostUpdateRecordMetadata(tx *gorm.DB, payload string) error {
	// piwww does not currently use the UpdateRecordMetadata route.
	// If this changes, this panic is here as a reminder that any piwww
	// mdstream tables, such as ProposalMetadata and StartVote, need to
	// be properly updated in this hook.

	// XXX Commented out as a temporary workaround for CMS using decred
	// plugin. This needs to be fixed once the plugin architecture is
	// sorted out.
	//
	// panic("cache decred plugin: hookPostUpdateRecordMetadata not implemented")

	return nil
}

// Hook executes the given decred plugin hook.
func (d *decred) Hook(tx *gorm.DB, hookID, payload string) error {
	log.Tracef("decred Hook: %v", hookID)

	switch hookID {
	case pluginHookPostNewRecord:
		return d.hookPostNewRecord(tx, payload)
	case pluginHookPostUpdateRecord:
		return d.hookPostUpdateRecord(tx, payload)
	case pluginHookPostUpdateRecordMetadata:
		return d.hookPostUpdateRecordMetadata(tx, payload)
	}

	return nil
}

// Exec executes a decred plugin command.  Plugin commands that write data to
// the cache require both the command payload and the reply payload.  Plugin
// commands that fetch data from the cache require only the command payload.
// All commands return the appropriate reply payload.
func (d *decred) Exec(cmd, cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred Exec: %v", cmd)

	switch cmd {
	case decredplugin.CmdAuthorizeVote:
		return d.cmdAuthorizeVote(cmdPayload, replyPayload)
	case decredplugin.CmdStartVote:
		return d.cmdStartVote(cmdPayload, replyPayload)
	case decredplugin.CmdStartVoteRunoff:
		return d.cmdStartVoteRunoff(cmdPayload, replyPayload)
	case decredplugin.CmdVoteDetails:
		return d.cmdVoteDetails(cmdPayload)
	case decredplugin.CmdBallot:
		return d.cmdNewBallot(cmdPayload, replyPayload)
	case decredplugin.CmdBestBlock:
		return "", nil
	case decredplugin.CmdNewComment:
		return d.cmdNewComment(cmdPayload, replyPayload)
	case decredplugin.CmdLikeComment:
		return d.cmdLikeComment(cmdPayload, replyPayload)
	case decredplugin.CmdCensorComment:
		return d.cmdCensorComment(cmdPayload, replyPayload)
	case decredplugin.CmdGetComment:
		return d.cmdGetComment(cmdPayload)
	case decredplugin.CmdGetComments:
		return d.cmdGetComments(cmdPayload)
	case decredplugin.CmdGetNumComments:
		return d.cmdGetNumComments(cmdPayload)
	case decredplugin.CmdProposalVotes:
		return d.cmdProposalVotes(cmdPayload)
	case decredplugin.CmdCommentLikes:
		return d.cmdCommentLikes(cmdPayload)
	case decredplugin.CmdProposalCommentsLikes:
		return d.cmdProposalCommentsLikes(cmdPayload)
	case decredplugin.CmdInventory:
		return d.cmdInventory()
	case decredplugin.CmdLoadVoteResults:
		return d.cmdLoadVoteResults(cmdPayload)
	case decredplugin.CmdTokenInventory:
		return d.cmdTokenInventory(cmdPayload)
	case decredplugin.CmdVoteSummary:
		return d.cmdVoteSummary(cmdPayload)
	case decredplugin.CmdBatchVoteSummary:
		return d.cmdBatchVoteSummary(cmdPayload)
	case decredplugin.CmdLinkedFrom:
		return d.cmdLinkedFrom(cmdPayload)
	}

	return "", cache.ErrInvalidPluginCmd
}

// createTables creates the cache tables needed by the decred plugin if they do
// not already exist. A decred plugin version record is inserted into the
// database during table creation.
//
// This function must be called within a transaction.
func (d *decred) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

	// Create decred plugin tables
	if !tx.HasTable(tableProposalMetadata) {
		err := tx.CreateTable(&ProposalMetadata{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableComments) {
		err := tx.CreateTable(&Comment{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableCommentLikes) {
		err := tx.CreateTable(&LikeComment{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableCastVotes) {
		err := tx.CreateTable(&CastVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableAuthorizeVotes) {
		err := tx.CreateTable(&AuthorizeVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteOptions) {
		err := tx.CreateTable(&VoteOption{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableStartVotes) {
		err := tx.CreateTable(&StartVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteOptionResults) {
		err := tx.CreateTable(&VoteOptionResult{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteResults) {
		err := tx.CreateTable(&VoteResults{}).Error
		if err != nil {
			return err
		}
	}

	// Check if a decred version record exists. Insert one
	// if no version record is found.
	if !tx.HasTable(tableVersions) {
		// This should never happen
		return fmt.Errorf("versions table not found")
	}

	var v Version
	err := tx.Where("id = ?", decredplugin.ID).Find(&v).Error
	if err == gorm.ErrRecordNotFound {
		err = tx.Create(
			&Version{
				ID:        decredplugin.ID,
				Version:   decredVersion,
				Timestamp: time.Now().Unix(),
			}).Error
	}

	return err
}

// droptTables drops all decred plugin tables from the cache and remove the
// decred plugin version record.
//
// This function must be called within a transaction.
func (d *decred) dropTables(tx *gorm.DB) error {
	// Drop decred plugin tables
	err := tx.DropTableIfExists(tableComments, tableCommentLikes,
		tableCastVotes, tableAuthorizeVotes, tableVoteOptions,
		tableStartVotes, tableVoteOptionResults, tableVoteResults,
		tableProposalMetadata).Error
	if err != nil {
		return err
	}

	// Remove decred plugin version record
	return tx.Delete(&Version{
		ID: decredplugin.ID,
	}).Error
}

// build the decred plugin cache using the passed in inventory.
//
// This function cannot be called using a transaction because it could
// potentially exceed cockroachdb's transaction size limit.
func (d *decred) build(ir *decredplugin.InventoryReply) error {
	log.Tracef("decred build")

	// Drop all decred plugin tables
	tx := d.recordsdb.Begin()
	err := d.dropTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("drop tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Create decred plugin tables
	tx = d.recordsdb.Begin()
	err = d.createTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("create tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Build comments cache
	log.Tracef("decred: building comments cache")
	for _, v := range ir.Comments {
		c := convertCommentFromDecred(v)
		err := d.recordsdb.Create(&c).Error
		if err != nil {
			log.Debugf("create comment failed on '%v'", c)
			return fmt.Errorf("newComment: %v", err)
		}
	}

	// Build like comments cache
	log.Tracef("decred: building like comments cache")
	for _, v := range ir.LikeComments {
		lc := convertLikeCommentFromDecred(v)
		err := d.recordsdb.Create(&lc).Error
		if err != nil {
			log.Debugf("newLikeComment failed on '%v'", lc)
			return fmt.Errorf("newLikeComment: %v", err)
		}
	}

	// Put authorize vote replies in a map for quick lookups
	avr := make(map[string]decredplugin.AuthorizeVoteReply,
		len(ir.AuthorizeVoteReplies)) // [receipt]AuthorizeVote
	for _, v := range ir.AuthorizeVoteReplies {
		avr[v.Receipt] = v
	}

	// Build authorize vote cache
	log.Tracef("decred: building authorize vote cache")
	for _, v := range ir.AuthorizeVotes {
		r, ok := avr[v.Receipt]
		if !ok {
			return fmt.Errorf("AuthorizeVoteReply not found %v",
				v.Token)
		}

		av, err := convertAuthorizeVoteFromDecred(v, r)
		if err != nil {
			return err
		}
		err = authorizeVoteInsert(d.recordsdb, *av)
		if err != nil {
			log.Debugf("authorizeVoteInsert failed on '%v'", av)
			return fmt.Errorf("authorizeVoteInsert: %v", err)
		}
	}

	// Build start vote cache
	log.Tracef("decred: building start vote cache")
	for _, v := range ir.StartVoteTuples {
		// Handle start vote versioning
		var sv StartVote
		switch v.StartVote.Version {
		case decredplugin.VersionStartVoteV1:
			svb := []byte(v.StartVote.Payload)
			sv1, err := decredplugin.DecodeStartVoteV1(svb)
			if err != nil {
				return fmt.Errorf("decode StartVoteV2 %v: %v",
					v.StartVote.Token, err)
			}
			svp, err := convertStartVoteV1FromDecred(*sv1, v.StartVoteReply)
			if err != nil {
				return fmt.Errorf("convertStartVoteV1FromDecred %v: %v",
					v.StartVote.Token, err)
			}
			sv = *svp
		case decredplugin.VersionStartVoteV2:
			svb := []byte(v.StartVote.Payload)
			sv2, err := decredplugin.DecodeStartVoteV2(svb)
			if err != nil {
				return fmt.Errorf("decode StartVoteV1 %v: %v",
					v.StartVote.Token, err)
			}
			svp, err := convertStartVoteV2FromDecred(*sv2, v.StartVoteReply)
			if err != nil {
				return fmt.Errorf("convertStartVoteV2FromDecred %v: %v",
					v.StartVote.Version, err)
			}
			sv = *svp
		}

		// Insert start vote record
		err = d.recordsdb.Create(&sv).Error
		if err != nil {
			return fmt.Errorf("insert StartVote: %v %v",
				err, sv.Token)
		}
	}

	// Build cast vote cache
	log.Tracef("decred: building cast vote cache")
	for _, v := range ir.CastVotes {
		cv := convertCastVoteFromDecred(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			log.Debugf("insert cast vote failed on '%v'", cv)
			return fmt.Errorf("insert cast vote: %v", err)
		}
	}

	// Build the ProposalMetadata cache. This metadata is not part of
	// the decredplugin InventoryReply. It is already stored in the
	// cached as a MetadataStream with an encoded payload. We need to
	// pull the ProposalMetadata out so it can be queried. Only the
	// ProposalMetadata for the most recent version of the proposal
	// is saved to the cache.

	// Lookup latest version of each record
	query := `SELECT a.*
            FROM records a
            LEFT OUTER JOIN records b
              ON a.token = b.token
              AND a.version < b.version
              WHERE b.token IS NULL`
	rows, err := d.recordsdb.Raw(query).Rows()
	if err != nil {
		return fmt.Errorf("lookup latest records: %v", err)
	}
	defer rows.Close()

	records := make([]Record, 0, 1024)
	for rows.Next() {
		var r Record
		err := d.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return err
		}
		records = append(records, r)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// Compile a list of record primary keys
	keys := make([]string, 0, len(records))
	for _, v := range records {
		keys = append(keys, v.Key)
	}

	// Lookup the files and metadata streams for each record
	err = d.recordsdb.
		Preload("Files").
		Preload("Metadata").
		Where(keys).
		Find(&records).
		Error
	if err != nil {
		return fmt.Errorf("lookup record metadata: %v", err)
	}

	for _, v := range records {
		pm, err := proposalMetadataNew(v)
		if err != nil {
			return err
		}
		if pm.Name == "" {
			// XXX we cannot return an error here until the plugin
			// architecture is sorted out. Right now, politeiad registers
			// the decred plugin by default. CMS needs a way to register
			// just the functionality it needs so that proposal specific
			// tables do not get built for CMS.
			// return fmt.Errorf("no proposal user metadata found %v",
			//	v.Token)

			continue
		}

		err = d.recordsdb.Create(pm).Error
		if err != nil {
			return fmt.Errorf("create: %v", err)
		}
	}

	return nil
}

// Build drops all existing decred plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the decred plugin
// cache.
func (d *decred) Build(payload string) error {
	log.Tracef("decred Build")

	// Decode the payload
	ir, err := decredplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Build the decred plugin cache. This is not run using
	// a transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err = d.build(ir)
	if err != nil {
		// Remove the version record. This will
		// force a rebuild on the next start up.
		err1 := d.recordsdb.Delete(&Version{
			ID: decredplugin.ID,
		}).Error
		if err1 != nil {
			panic("the cache is out of sync and will not rebuild" +
				"automatically; a rebuild must be forced")
		}
	}

	return err
}

// Setup creates the decred plugin tables if they do not already exist.  A
// decred plugin version record is inserted into the database during table
// creation.
func (d *decred) Setup() error {
	log.Tracef("decred: Setup")

	tx := d.recordsdb.Begin()
	err := d.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CheckVersion retrieves the decred plugin version record from the database,
// if one exists, and checks that it matches the version of the current decred
// plugin cache implementation.
func (d *decred) CheckVersion() error {
	log.Tracef("decred: CheckVersion")

	// Sanity check. Ensure version table exists.
	if !d.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record. If the version is not found or
	// if there is a version mismatch, return an error so
	// that the decred plugin cache can be built/rebuilt.
	var v Version
	err := d.recordsdb.
		Where("id = ?", decredplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		log.Debugf("version record not found for ID '%v'",
			decredplugin.ID)
		err = cache.ErrNoVersionRecord
	} else if v.Version != decredVersion {
		log.Debugf("version mismatch for ID '%v': got %v, want %v",
			decredplugin.ID, v.Version, decredVersion)
		err = cache.ErrWrongVersion
	}

	return err
}

// newDecredPlugin returns a cache decred plugin context.
func newDecredPlugin(db *gorm.DB, p cache.Plugin) *decred {
	log.Tracef("newDecredPlugin")
	return &decred{
		recordsdb: db,
		version:   decredVersion,
		settings:  p.Settings,
	}
}
