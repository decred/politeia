// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/cmsplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// cmsVersion is the version of the cache implementation of
	// cms plugin. This may differ from the cmsplugin package
	// version.
	cmsVersion = "1.1"

	// CMS plugin table names
	tableDCCCastVotes   = "dcc_cast_votes"
	tableDCCVoteOptions = "dcc_vote_options"
	tableDCCStartVotes  = "dcc_start_votes"
	tableDCCVoteResults = "dcc_vote_results"

	// Vote option IDs
	voteOptionDCCIDApproved = "yes"
	voteOptionDCCIDRejected = "no"
)

// cms implements the PluginDriver interface.
type cms struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of cms cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// newAuthorizeVote creates an AuthorizeVote record and inserts it into the
// database.  If a previous AuthorizeVote record exists for the passed in
// proposal and version, it will be deleted before the new AuthorizeVote record
// is inserted.
//
// This function must be called within a transaction.
func (d *cms) newAuthorizeVote(tx *gorm.DB, av AuthorizeVote) error {
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
func (d *cms) cmdAuthorizeVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdAuthorizeVote")

	av, err := cmsplugin.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	avr, err := cmsplugin.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	v, err := strconv.ParseUint(avr.RecordVersion, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse version '%v' failed: %v",
			avr.RecordVersion, err)
	}

	// Run update in a transaction
	a := convertAuthorizeVoteFromCMS(*av, *avr, v)
	tx := d.recordsdb.Begin()
	err = d.newAuthorizeVote(tx, a)
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("newAuthorizeVote: %v", err)
	}

	// Commit transaction
	err = tx.Commit().Error
	if err != nil {
		return "", fmt.Errorf("commit transaction: %v", err)
	}

	return replyPayload, nil
}

// newStartVote inserts a StartVote record into the database.  This function
// has a database parameter so that it can be called inside of a transaction
// when required.
func (d *cms) newStartVote(db *gorm.DB, sv StartVote) error {
	return db.Create(&sv).Error
}

// cmdStartVote creates a StartVote record using the passed in payloads and
// inserts it into the database.
func (d *cms) cmdStartVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdStartVote")

	sv, err := cmsplugin.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := cmsplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse end height '%v': %v",
			svr.EndHeight, err)
	}

	s := convertStartVoteFromCMS(*sv, *svr, endHeight)
	err = d.newStartVote(d.recordsdb, s)
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

// cmdVoteDetails returns the AuthorizeVote and StartVote records for the
// passed in record token.
func (d *cms) cmdVoteDetails(payload string) (string, error) {
	log.Tracef("cms cmdVoteDetails")

	vd, err := cmsplugin.DecodeVoteDetails([]byte(payload))
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
	var sv StartVote
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

	// Prepare reply
	dav := convertAuthorizeVoteToCMS(av)
	dsv, dsvr := convertStartVoteToCMS(sv)
	vdr := cmsplugin.VoteDetailsReply{
		AuthorizeVote:  dav,
		StartVote:      dsv,
		StartVoteReply: dsvr,
	}
	vdrb, err := cmsplugin.EncodeVoteDetailsReply(vdr)
	if err != nil {
		return "", err
	}

	return string(vdrb), nil
}

// cmdNewBallot creates CastVote records using the passed in payloads and
// inserts them into the database.
func (d *cms) cmdNewBallot(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdNewBallot")

	b, err := cmsplugin.DecodeBallot([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	br, err := cmsplugin.DecodeBallotReply([]byte(replyPayload))
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
				v.Token, v.Pubkey)
			continue
		}

		cv := convertCastVoteFromCMS(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			return "", err
		}
	}

	return replyPayload, nil
}

// cmdProposalVotes returns the StartVote record and all CastVote records for
// the passed in record token.
func (d *cms) cmdProposalVotes(payload string) (string, error) {
	log.Tracef("cms cmdProposalVotes")

	vr, err := cmsplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup start vote
	var sv StartVote
	err = d.recordsdb.
		Where("token = ?", vr.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// A start vote may note exist if the voting period has not
		// been started yet. This is ok.
	} else if err != nil {
		return "", fmt.Errorf("start vote lookup failed: %v", err)
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
	dsv, _ := convertStartVoteToCMS(sv)
	dcv := make([]cmsplugin.CastVote, 0, len(cv))
	for _, v := range cv {
		dcv = append(dcv, convertCastVoteToCMS(v))
	}

	vrr := cmsplugin.VoteResultsReply{
		StartVote: dsv,
		CastVotes: dcv,
	}

	vrrb, err := cmsplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", err
	}

	return string(vrrb), nil
}

// cmdInventory returns the cms plugin inventory.
func (d *cms) cmdInventory() (string, error) {
	log.Tracef("cms cmdInventory")

	return "", nil
}

// newVoteResults creates a VoteResults record for a proposal and inserts it
// into the cache. A VoteResults record should only be created for proposals
// once the voting period has ended.
func (d *cms) newVoteResults(token string) error {
	log.Tracef("newVoteResults %v", token)

	// Lookup start vote
	var sv StartVote
	err := d.recordsdb.
		Where("token = ?", token).
		Preload("Options").
		Find(&sv).
		Error
	if err != nil {
		return fmt.Errorf("lookup start vote: %v", err)
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

	// Tally cast votes
	tally := make(map[string]uint64) // [voteBit]voteCount
	for _, v := range cv {
		tally[v.VoteBit]++
	}

	// Create vote option results
	results := make([]VoteOptionResult, 0, len(sv.Options))
	for _, v := range sv.Options {
		voteBit := strconv.FormatUint(v.Bits, 16)
		voteCount := tally[voteBit]

		results = append(results, VoteOptionResult{
			Key:    token + voteBit,
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

	// XXX: this only supports proposals with yes/no
	// voting options. Multiple voting option support
	// will need to be added in the future.
	var approvedVotes uint64
	for _, v := range results {
		if v.Option.ID == voteOptionDCCIDApproved {
			approvedVotes = v.Votes
		}
	}

	var approved bool
	switch {
	case total < quorum:
		// Quorum not met
	case approvedVotes < pass:
		// Pass percentage not met
	default:
		// Vote was approved
		approved = true
	}

	// Create a vote results entry
	err = d.recordsdb.Create(&VoteResults{
		Token:    token,
		Approved: approved,
		Results:  results,
	}).Error
	if err != nil {
		return fmt.Errorf("new vote results: %v", err)
	}

	return nil
}

// cmdLoadVoteResults creates vote results entries for any proposals that have
// a finished voting period but have not yet been added to the vote results
// table. The vote results table is lazy loaded.
func (d *cms) cmdLoadVoteResults(payload string) (string, error) {
	log.Tracef("cmdLoadVoteResults")

	lvs, err := cmsplugin.DecodeLoadVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Find proposals that have a finished voting period but
	// have not yet been added to the vote results table.
	q := `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND vote_results.token IS NULL`
	rows, err := d.recordsdb.Raw(q, lvs.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("no vote results: %v", err)
	}
	defer rows.Close()

	var token string
	tokens := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		tokens = append(tokens, token)
	}

	// Create vote result entries
	for _, v := range tokens {
		err := d.newVoteResults(v)
		if err != nil {
			return "", fmt.Errorf("newVoteResults %v: %v", v, err)
		}
	}

	// Prepare reply
	r := cmsplugin.LoadVoteResultsReply{}
	reply, err := cmsplugin.EncodeLoadVoteResultsReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdTokenInventory returns the tokens of all records in the cache,
// categorized by stage of the voting process.
func (d *cms) cmdTokenInventory(payload string) (string, error) {
	log.Tracef("cms cmdDCCInventory")

	ti, err := cmsplugin.DecodeDCCInventory([]byte(payload))
	if err != nil {
		return "", err
	}

	// The token inventory call cannot be completed if there
	// are any proposals that have finished voting but that
	// don't have an entry in the vote results table yet.
	// Fail here if any are found.
	q := `SELECT start_votes.token
        FROM start_votes
        LEFT OUTER JOIN vote_results
          ON start_votes.token = vote_results.token
          WHERE start_votes.end_height <= ?
          AND vote_results.token IS NULL`
	rows, err := d.recordsdb.Raw(q, ti.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("no vote results: %v", err)
	}
	defer rows.Close()

	var token string
	missing := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		missing = append(missing, token)
	}

	if len(missing) > 0 {
		// Return a ErrRecordNotFound to indicate one
		// or more vote result records were not found.
		return "", cache.ErrRecordNotFound
	}

	// Pre voting period tokens. This query returns the
	// tokens of the most recent version of all records that
	// are public and do not have an associated StartVote
	// record, ordered by timestamp in descending order.
	q = `SELECT a.token
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
	rows, err = d.recordsdb.Raw(q, pd.RecordStatusPublic).Rows()
	if err != nil {
		return "", fmt.Errorf("pre: %v", err)
	}
	defer rows.Close()

	pre := make([]string, 0, 1024)
	for rows.Next() {
		rows.Scan(&token)
		pre = append(pre, token)
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
		rows.Scan(&token)
		active = append(active, token)
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
		rows.Scan(&token)
		approved = append(approved, token)
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
		rows.Scan(&token)
		rejected = append(rejected, token)
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
		rows.Scan(&token)
		abandoned = append(abandoned, token)
	}

	// Setup reply
	tir := cmsplugin.TokenInventoryReply{
		Pre:       pre,
		Active:    active,
		Approved:  approved,
		Rejected:  rejected,
		Abandoned: abandoned,
	}

	// Add unvetted records if specified
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
			rows.Scan(&token)
			unreviewed = append(unreviewed, token)
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
			rows.Scan(&token)
			censored = append(censored, token)
		}

		// Update reply
		tir.Unreviewed = unreviewed
		tir.Censored = censored
	}

	// Encode reply
	reply, err := cmsplugin.EncodeTokenInventoryReply(tir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// getAuthorizeVotesForRecords looks up vote authorizations in the cache for a set
// of records.
func (d *cms) getAuthorizeVotesForRecords(records map[string]Record) (map[string]AuthorizeVote, error) {
	authorizeVotes := make(map[string]AuthorizeVote)

	if len(records) == 0 {
		return authorizeVotes, nil
	}

	keys := make([]string, 0, len(records))
	for token, record := range records {
		keys = append(keys, token+strconv.FormatUint(record.Version, 10))
	}

	avs := make([]AuthorizeVote, 0, len(keys))
	err := d.recordsdb.
		Where("key IN (?)", keys).
		Find(&avs).
		Error
	if err != nil {
		return nil, err
	}

	for _, av := range avs {
		authorizeVotes[av.Token] = av
	}

	return authorizeVotes, nil
}

// getStartVotes looks up the start votes for records which have been
// authorized to start voting.
func (d *cms) getStartVotes(authorizeVotes map[string]AuthorizeVote) (map[string]StartVote, error) {
	startVotes := make(map[string]StartVote)

	if len(authorizeVotes) == 0 {
		return startVotes, nil
	}

	tokens := make([]string, 0, len(authorizeVotes))
	for token := range authorizeVotes {
		tokens = append(tokens, token)
	}

	svs := make([]StartVote, 0, len(tokens))
	err := d.recordsdb.
		Where("token IN (?)", tokens).
		Preload("Options").
		Find(&svs).
		Error

	if err != nil {
		return nil, err
	}
	for _, sv := range svs {
		startVotes[sv.Token] = sv
	}

	return startVotes, nil
}

// lookupResultsForVoteOptions looks in the CastVote table to see how many
// votes each option has received.
func (d *cms) lookupResultsForVoteOptions(options []VoteOption) ([]cmsplugin.VoteOptionResult, error) {
	results := make([]cmsplugin.VoteOptionResult, 0, len(options))

	for _, v := range options {
		var votes uint64
		tokenVoteBit := v.Token + strconv.FormatUint(v.Bits, 16)
		err := d.recordsdb.
			Model(&CastVote{}).
			Where("token_vote_bit = ?", tokenVoteBit).
			Count(&votes).
			Error
		if err != nil {
			return nil, err
		}

		results = append(results,
			cmsplugin.VoteOptionResult{
				ID:          v.ID,
				Description: v.Description,
				Bits:        v.Bits,
				Votes:       votes,
			})
	}

	return results, nil
}

// getVoteResults retrieves vote results for records that have begun the voting
// process. Results are lazily loaded into this table, so some results are
// manually looked up in the CastVote table.
func (d *cms) getVoteResults(startVotes map[string]StartVote) (map[string][]cmsplugin.VoteOptionResult, error) {
	results := make(map[string][]cmsplugin.VoteOptionResult)

	if len(startVotes) == 0 {
		return results, nil
	}

	tokens := make([]string, 0, len(startVotes))
	for token := range startVotes {
		tokens = append(tokens, token)
	}

	vrs := make([]VoteResults, 0, len(tokens))
	err := d.recordsdb.
		Where("token IN (?)", tokens).
		Preload("Results").
		Preload("Results.Option").
		Find(&vrs).
		Error
	if err != nil {
		return nil, err
	}

	for _, vr := range vrs {
		results[vr.Token] = convertVoteOptionResultsToCMS(vr.Results)
	}

	for token, sv := range startVotes {
		_, ok := results[token]
		if ok {
			continue
		}

		res, err := d.lookupResultsForVoteOptions(sv.Options)
		if err != nil {
			return nil, err
		}

		results[token] = res
	}

	return results, nil
}

func (d *cms) cmdBatchVoteSummary(payload string) (string, error) {
	log.Tracef("cmdBatchVoteSummary")

	bvs, err := cmsplugin.DecodeBatchVoteSummary([]byte(payload))
	if err != nil {
		return "", err
	}

	// This query gets the latest version of each record
	query := `SELECT a.* FROM records a
	LEFT OUTER JOIN records b
		ON a.token = b.token AND a.version < b.version
	WHERE b.token IS NULL AND a.token IN (?)`

	rows, err := d.recordsdb.Raw(query, bvs.Tokens).Rows()
	if err != nil {
		return "", err
	}
	defer rows.Close()

	records := make(map[string]Record, len(bvs.Tokens))
	for rows.Next() {
		var r Record
		err := d.recordsdb.ScanRows(rows, &r)
		if err != nil {
			return "", err
		}
		records[r.Token] = r
	}

	authorizeVotes, err := d.getAuthorizeVotesForRecords(records)
	if err != nil {
		return "", fmt.Errorf("lookup authorize votes: %v", err)
	}

	startVotes, err := d.getStartVotes(authorizeVotes)
	if err != nil {
		return "", fmt.Errorf("lookup start vote: %v", err)
	}

	results, err := d.getVoteResults(startVotes)
	if err != nil {
		return "", fmt.Errorf("lookup vote results: %v", err)
	}

	summaries := make(map[string]cmsplugin.VoteSummaryReply,
		len(bvs.Tokens))
	for token := range records {
		av := authorizeVotes[token]
		sv := startVotes[token]
		res := results[token]

		var endHeight string
		if sv.EndHeight != 0 {
			endHeight = strconv.FormatUint(sv.EndHeight, 10)
		}

		authorized := av.Action == cmsplugin.AuthVoteActionAuthorize
		vsr := cmsplugin.VoteSummaryReply{
			Authorized:          authorized,
			Duration:            sv.Duration,
			EndHeight:           endHeight,
			EligibleTicketCount: sv.EligibleTicketCount,
			QuorumPercentage:    sv.QuorumPercentage,
			PassPercentage:      sv.PassPercentage,
			Results:             res,
		}
		summaries[token] = vsr
	}

	bvsr := cmsplugin.BatchVoteSummaryReply{
		Summaries: summaries,
	}
	reply, err := cmsplugin.EncodeBatchVoteSummaryReply(bvsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (d *cms) cmdVoteSummary(payload string) (string, error) {
	log.Tracef("cmdVoteSummary")

	vs, err := cmsplugin.DecodeVoteSummary([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup the most recent record version
	var r Record
	err = d.recordsdb.
		Where("records.token = ?", vs.Token).
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

	// Declare here to prevent goto errors
	results := make([]cmsplugin.VoteOptionResult, 0, 16)
	var (
		av AuthorizeVote
		sv StartVote
		vr VoteResults
	)

	// Lookup authorize vote
	key := vs.Token + strconv.FormatUint(r.Version, 10)
	err = d.recordsdb.
		Where("key = ?", key).
		Find(&av).
		Error
	if err == gorm.ErrRecordNotFound {
		// If an authorize vote doesn't exist
		// then there is no need to continue.
		goto sendReply
	} else if err != nil {
		return "", fmt.Errorf("lookup authorize vote: %v", err)
	}

	// Lookup start vote
	err = d.recordsdb.
		Where("token = ?", vs.Token).
		Preload("Options").
		Find(&sv).
		Error
	if err == gorm.ErrRecordNotFound {
		// If an start vote doesn't exist then
		// there is no need to continue.
		goto sendReply
	} else if err != nil {
		return "", fmt.Errorf("lookup start vote: %v", err)
	}

	// Lookup vote results
	err = d.recordsdb.
		Where("token = ?", vs.Token).
		Preload("Results").
		Preload("Results.Option").
		Find(&vr).
		Error
	if err == gorm.ErrRecordNotFound {
		// A vote results record was not found. This means that
		// the vote is either still active or has not been lazy
		// loaded yet. The vote results will need to be looked
		// up manually.
	} else if err != nil {
		return "", fmt.Errorf("lookup vote results: %v", err)
	} else {
		// Vote results record exists. We have all of the data
		// that we need to send the reply.
		vor := convertVoteOptionResultsToCMS(vr.Results)
		results = append(results, vor...)
		goto sendReply
	}

	// Lookup vote results manually
	results, err = d.lookupResultsForVoteOptions(sv.Options)
	if err != nil {
		return "", fmt.Errorf("count cast votes: %v", err)
	}

sendReply:
	// Return "" not "0" if end height doesn't exist
	var endHeight string
	if sv.EndHeight != 0 {
		endHeight = strconv.FormatUint(sv.EndHeight, 10)
	}

	vsr := cmsplugin.VoteSummaryReply{
		Authorized:          av.Action == cmsplugin.AuthVoteActionAuthorize,
		Duration:            sv.Duration,
		EndHeight:           endHeight,
		EligibleTicketCount: sv.EligibleTicketCount,
		QuorumPercentage:    sv.QuorumPercentage,
		PassPercentage:      sv.PassPercentage,
		Results:             results,
	}
	reply, err := cmsplugin.EncodeVoteSummaryReply(vsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Exec executes a cms plugin command.  Plugin commands that write data to
// the cache require both the command payload and the reply payload.  Plugin
// commands that fetch data from the cache require only the command payload.
// All commands return the appropriate reply payload.
func (d *cms) Exec(cmd, cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms Exec: %v", cmd)

	switch cmd {
	case cmsplugin.CmdAuthorizeVote:
		return d.cmdAuthorizeVote(cmdPayload, replyPayload)
	case cmsplugin.CmdStartVote:
		return d.cmdStartVote(cmdPayload, replyPayload)
	case cmsplugin.CmdVoteDetails:
		return d.cmdVoteDetails(cmdPayload)
	case cmsplugin.CmdBallot:
		return d.cmdNewBallot(cmdPayload, replyPayload)
	case cmsplugin.CmdInventory:
		return d.cmdInventory()
	case cmsplugin.CmdLoadVoteResults:
		return d.cmdLoadVoteResults(cmdPayload)
	case cmsplugin.CmdTokenInventory:
		return d.cmdTokenInventory(cmdPayload)
	case cmsplugin.CmdVoteSummary:
		return d.cmdVoteSummary(cmdPayload)
	case cmsplugin.CmdBatchVoteSummary:
		return d.cmdBatchVoteSummary(cmdPayload)
	}

	return "", cache.ErrInvalidPluginCmd
}

// createTables creates the cache tables needed by the cms plugin if they do
// not already exist. A cms plugin version record is inserted into the
// database during table creation.
//
// This function must be called within a transaction.
func (d *cms) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

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

	// Check if a cms version record exists. Insert one
	// if no version record is found.
	if !tx.HasTable(tableVersions) {
		// This should never happen
		return fmt.Errorf("versions table not found")
	}

	var v Version
	err := tx.Where("id = ?", cmsplugin.ID).Find(&v).Error
	if err == gorm.ErrRecordNotFound {
		err = tx.Create(
			&Version{
				ID:        cmsplugin.ID,
				Version:   cmsVersion,
				Timestamp: time.Now().Unix(),
			}).Error
	}

	return err
}

// droptTables drops all cms plugin tables from the cache and remove the
// cms plugin version record.
//
// This function must be called within a transaction.
func (d *cms) dropTables(tx *gorm.DB) error {
	// Drop cms plugin tables
	err := tx.DropTableIfExists(tableCastVotes, tableAuthorizeVotes,
		tableVoteOptions, tableStartVotes, tableVoteOptionResults,
		tableVoteResults).
		Error
	if err != nil {
		return err
	}

	// Remove cms plugin version record
	return tx.Delete(&Version{
		ID: cmsplugin.ID,
	}).Error
}

// build the cms plugin cache using the passed in inventory.
//
// This function cannot be called using a transaction because it could
// potentially exceed cockroachdb's transaction size limit.
func (d *cms) build(ir *cmsplugin.InventoryReply) error {
	log.Tracef("cms build")

	// Drop all cms plugin tables
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

	// Create cms plugin tables
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

	// Put authorize vote replies in a map for quick lookups
	avr := make(map[string]cmsplugin.AuthorizeVoteReply,
		len(ir.AuthorizeVoteReplies)) // [receipt]AuthorizeVote
	for _, v := range ir.AuthorizeVoteReplies {
		avr[v.Receipt] = v
	}

	// Build authorize vote cache
	log.Tracef("cms: building authorize vote cache")
	for _, v := range ir.AuthorizeVotes {
		r, ok := avr[v.Receipt]
		if !ok {
			return fmt.Errorf("AuthorizeVoteReply not found %v",
				v.Token)
		}

		rv, err := strconv.ParseUint(r.RecordVersion, 10, 64)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", r)
			return fmt.Errorf("parse version '%v' failed: %v",
				r.RecordVersion, err)
		}

		av := convertAuthorizeVoteFromCMS(v, r, rv)
		err = d.newAuthorizeVote(d.recordsdb, av)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", av)
			return fmt.Errorf("newAuthorizeVote: %v", err)
		}
	}

	// Build start vote cache
	log.Tracef("cms: building start vote cache")
	for _, v := range ir.StartVoteTuples {
		endHeight, err := strconv.ParseUint(v.StartVoteReply.EndHeight, 10, 64)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", v)
			return fmt.Errorf("parse end height '%v': %v",
				v.StartVoteReply.EndHeight, err)
		}

		sv := convertStartVoteFromCMS(v.StartVote,
			v.StartVoteReply, endHeight)
		err = d.newStartVote(d.recordsdb, sv)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", sv)
			return fmt.Errorf("newStartVote: %v", err)
		}
	}

	// Build cast vote cache
	log.Tracef("cms: building cast vote cache")
	for _, v := range ir.CastVotes {
		cv := convertCastVoteFromCMS(v)
		err := d.recordsdb.Create(&cv).Error
		if err != nil {
			log.Debugf("insert cast vote failed on '%v'", cv)
			return fmt.Errorf("insert cast vote: %v", err)
		}
	}

	return nil
}

// Build drops all existing cms plugin tables from the database, recreates
// them, then uses the passed in inventory payload to build the cms plugin
// cache.
func (d *cms) Build(payload string) error {
	log.Tracef("cms Build")

	// Decode the payload
	ir, err := cmsplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Build the cms plugin cache. This is not run using
	// a transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err = d.build(ir)
	if err != nil {
		// Remove the version record. This will
		// force a rebuild on the next start up.
		err1 := d.recordsdb.Delete(&Version{
			ID: cmsplugin.ID,
		}).Error
		if err1 != nil {
			panic("the cache is out of sync and will not rebuild" +
				"automatically; a rebuild must be forced")
		}
	}

	return err
}

// Setup creates the cms plugin tables if they do not already exist.  A
// cms plugin version record is inserted into the database during table
// creation.
func (d *cms) Setup() error {
	log.Tracef("cms: Setup")

	tx := d.recordsdb.Begin()
	err := d.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CheckVersion retrieves the cms plugin version record from the database,
// if one exists, and checks that it matches the version of the current cms
// plugin cache implementation.
func (d *cms) CheckVersion() error {
	log.Tracef("cms: CheckVersion")

	// Sanity check. Ensure version table exists.
	if !d.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record. If the version is not found or
	// if there is a version mismatch, return an error so
	// that the cms plugin cache can be built/rebuilt.
	var v Version
	err := d.recordsdb.
		Where("id = ?", cmsplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		log.Debugf("version record not found for ID '%v'",
			cmsplugin.ID)
		err = cache.ErrNoVersionRecord
	} else if v.Version != cmsVersion {
		log.Debugf("version mismatch for ID '%v': got %v, want %v",
			cmsplugin.ID, v.Version, cmsVersion)
		err = cache.ErrWrongVersion
	}

	return err
}

// newCMSPlugin returns a cache cms plugin context.
func newCMSPlugin(db *gorm.DB, p cache.Plugin) *cms {
	log.Tracef("newCMSPlugin")
	return &cms{
		recordsdb: db,
		version:   cmsVersion,
		settings:  p.Settings,
	}
}
