// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// cmsVersion is the version of the cache implementation of
	// cms plugin. This may differ from the cmsplugin package
	// version.
	cmsVersion = "1"

	tableCastDCCVotes         = "cast_dcc_votes"
	tableStartDCCVotes        = "start_dcc_votes"
	tableDCCUserWeights       = "user_weights"
	tableVoteDCCOptionResults = "vote_dcc_options_results"
	tableVoteDCCOptions       = "vote_dcc_options"
	tableVoteDCCResults       = "vote_dcc_results"
)

// cms implements the PluginDriver interface.
type cms struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of cms cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// newStartDCCVote inserts a StartDCCVote record into the database.  This function
// has a database parameter so that it can be called inside of a transaction
// when required.
func (c *cms) newStartDCCVote(db *gorm.DB, sv StartDCCVote) error {
	return db.Create(&sv).Error
}

// cmdStartVote creates a StartDCCVote record using the passed in payloads and
// inserts it into the database.
func (c *cms) cmdStartVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdStartDCCVote")

	sv, err := cmsplugin.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := cmsplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	s := convertStartVoteFromCMS(sv, svr, svr.EndHeight)
	err = c.newStartDCCVote(c.recordsdb, s)
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

// cmdCastVote creates CastVote records using the passed in payloads and
// inserts them into the database.
func (c *cms) cmdCastVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms cmdNewCastVote")

	b, err := cmsplugin.DecodeCastVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	if b.Signature == "" {
		log.Debugf("cmdNewCastVote: vote receipt not found %v %v",
			b.Token, b.UserID)
		return "", nil
	}
	cv := convertCastVoteFromCMS(*b)
	err = c.recordsdb.Create(&cv).Error
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

// cmdProposalVotes returns the StartVote record and all CastVote records for
// the passed in record token.
func (c *cms) cmdDCCVotes(payload string) (string, error) {
	log.Tracef("cms cmdProposalVotes")

	vr, err := cmsplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup start vote
	var sv StartDCCVote
	err = c.recordsdb.
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
	var cv []CastDCCVote
	err = c.recordsdb.
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
func (c *cms) cmdInventory() (string, error) {
	log.Tracef("cms cmdInventory")

	// XXX we don't currently return anything for inventory here

	return "", nil
}

// cmdLoadVoteResults creates vote results entries for any dccs that have
// a finished voting period but have not yet been added to the vote results
// table. The vote results table is lazy loaded.
func (c *cms) cmdLoadVoteResults(payload string) (string, error) {
	log.Tracef("cmdLoadVoteResults")

	lvs, err := cmsplugin.DecodeLoadVoteResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Find dccs that have a finished voting period but
	// have not yet been added to the vote results table.
	q := `SELECT start__dcc_votes.token
        FROM start_dcc_votes
        LEFT OUTER JOIN vote_dcc_results
          ON start_dcc_votes.token = vote_dcc_results.token
          WHERE start_dcc_votes.end_height <= ?
          AND vote_dcc_results.token IS NULL`
	rows, err := c.recordsdb.Raw(q, lvs.BestBlock).Rows()
	if err != nil {
		return "", fmt.Errorf("no vote results: %v", err)
	}
	defer rows.Close()

	var token string
	tokens := make([]string, 0, 1024)
	for rows.Next() {
		err = rows.Scan(&token)
		if err != nil {
			return "", err
		}
		tokens = append(tokens, token)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}

	// Create vote result entries
	for _, v := range tokens {
		err := c.newVoteResults(v)
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

// newVoteResults creates a VoteDCCResults record for a proposal and inserts it
// into the cache. A VoteDCCResults record should only be created for proposals
// once the voting period has ended.
func (c *cms) newVoteResults(token string) error {
	log.Tracef("newVoteResults %v", token)

	// Lookup start vote
	var sv StartDCCVote
	err := c.recordsdb.
		Where("token = ?", token).
		Preload("Options").
		Find(&sv).
		Error
	if err != nil {
		return fmt.Errorf("lookup start vote: %v", err)
	}

	// Lookup cast votes
	var cv []CastDCCVote
	err = c.recordsdb.
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
	results := make([]VoteDCCOptionResult, 0, len(sv.Options))
	for _, v := range sv.Options {
		voteBit := strconv.FormatUint(v.Bits, 16)
		voteCount := tally[voteBit]

		results = append(results, VoteDCCOptionResult{
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

	eligible := sv.EligibleUserIDs
	quorum := uint64(int(sv.QuorumPercentage) / 100 * len(eligible))
	pass := uint64(float64(sv.PassPercentage) / 100 * float64(total))

	var approvedVotes uint64
	for _, v := range results {
		if v.Option.ID == cmsplugin.DCCApprovalString {
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
	err = c.recordsdb.Create(&VoteDCCResults{
		Token:    token,
		Approved: approved,
		Results:  results,
	}).Error
	if err != nil {
		return fmt.Errorf("new vote results: %v", err)
	}

	return nil
}

// getStartVotes looks up the start votes for records which have been
// authorized to start voting.
func (c *cms) getStartVotes(records map[string]Record) (map[string]StartDCCVote, error) {
	startVotes := make(map[string]StartDCCVote)

	if len(records) == 0 {
		return startVotes, nil
	}

	keys := make([]string, 0, len(records))
	for token, record := range records {
		keys = append(keys, token+strconv.FormatUint(record.Version, 10))
	}

	svs := make([]StartDCCVote, 0, len(keys))
	err := c.recordsdb.
		Where("key IN (?)", keys).
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

// lookupResultsForVoteDCCOptions looks in the CastDCCVote table to see how many
// votes each option has received.
func (c *cms) lookupResultsForVoteDCCOptions(options []VoteDCCOption) ([]cmsplugin.VoteOptionResult, error) {
	results := make([]cmsplugin.VoteOptionResult, 0, len(options))

	for _, v := range options {
		var votes uint64
		tokenVoteBit := v.Token + strconv.FormatUint(v.Bits, 16)
		err := c.recordsdb.
			Model(&CastDCCVote{}).
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
// manually looked up in the CastDCCVote table.
func (c *cms) getVoteResults(startVotes map[string]StartDCCVote) (map[string][]cmsplugin.VoteOptionResult, error) {
	results := make(map[string][]cmsplugin.VoteOptionResult)

	if len(startVotes) == 0 {
		return results, nil
	}

	tokens := make([]string, 0, len(startVotes))
	for token := range startVotes {
		tokens = append(tokens, token)
	}

	vrs := make([]VoteResults, 0, len(tokens))
	err := c.recordsdb.
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

		res, err := c.lookupResultsForVoteDCCOptions(sv.Options)
		if err != nil {
			return nil, err
		}

		results[token] = res
	}

	return results, nil
}

// Exec executes a cms plugin command.  Plugin commands that write data to
// the cache require both the command payload and the reply payload.  Plugin
// commands that fetch data from the cache require only the command payload.
// All commands return the appropriate reply payload.
func (c *cms) Exec(cmd, cmdPayload, replyPayload string) (string, error) {
	log.Tracef("cms Exec: %v", cmd)

	switch cmd {
	}

	return "", cache.ErrInvalidPluginCmd
}

// createTables creates the cache tables needed by the cms plugin if they do
// not already exist. A cms plugin version record is inserted into the
// database during table creation.
//
// This function must be called within a transaction.
func (c *cms) createTables(tx *gorm.DB) error {
	log.Tracef("createTables")

	if !tx.HasTable(tableCastDCCVotes) {
		err := tx.CreateTable(&CastDCCVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteDCCOptions) {
		err := tx.CreateTable(&VoteDCCOption{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableStartDCCVotes) {
		err := tx.CreateTable(&StartDCCVote{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteDCCOptionResults) {
		err := tx.CreateTable(&VoteDCCOptionResult{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableVoteDCCResults) {
		err := tx.CreateTable(&VoteDCCResults{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableDCCUserWeights) {
		err := tx.CreateTable(&DCCUserWeight{}).Error
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

// dropTables drops all cms plugin tables from the cache and remove the
// cms plugin version record.
//
// This function must be called within a transaction.
func (c *cms) dropTables(tx *gorm.DB) error {
	// Drop cms plugin tables
	err := tx.DropTableIfExists(tableCastDCCVotes, tableStartDCCVotes,
		tableVoteDCCOptions, tableVoteDCCOptionResults, tableVoteDCCResults,
		tableDCCUserWeights).
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
func (c *cms) build(ir *cmsplugin.InventoryReply) error {
	log.Tracef("cms build")

	// Drop all cms plugin tables
	tx := c.recordsdb.Begin()
	err := c.dropTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("drop tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Create cms plugin tables
	tx = c.recordsdb.Begin()
	err = c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("create tables: %v", err)
	}
	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Build start vote cache
	log.Tracef("cms: building start vote cache")
	for _, v := range ir.StartVoteTuples {
		sv := convertStartVoteFromCMS(v.StartVote,
			v.StartVoteReply, v.StartVoteReply.EndHeight)
		err = c.newStartDCCVote(c.recordsdb, sv)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", sv)
			return fmt.Errorf("newStartVote: %v", err)
		}
	}

	// Build cast vote cache
	log.Tracef("cms: building cast vote cache")
	for _, v := range ir.CastVotes {
		cv := convertCastVoteFromCMS(v)
		err := c.recordsdb.Create(&cv).Error
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
func (c *cms) Build(payload string) error {
	log.Tracef("cms Build")

	// Decode the payload
	ir, err := cmsplugin.DecodeInventoryReply([]byte(payload))
	if err != nil {
		return fmt.Errorf("DecodeInventoryReply: %v", err)
	}

	// Build the cms plugin cache. This is not run using
	// a transaction because it could potentially exceed
	// cockroachdb's transaction size limit.
	err = c.build(ir)
	if err != nil {
		// Remove the version record. This will
		// force a rebuild on the next start up.
		err1 := c.recordsdb.Delete(&Version{
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
func (c *cms) Setup() error {
	log.Tracef("cms: Setup")

	tx := c.recordsdb.Begin()
	err := c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// CheckVersion retrieves the cms plugin version record from the database,
// if one exists, and checks that it matches the version of the current cms
// plugin cache implementation.
func (c *cms) CheckVersion() error {
	log.Tracef("cms: CheckVersion")

	// Sanity check. Ensure version table exists.
	if !c.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record. If the version is not found or
	// if there is a version mismatch, return an error so
	// that the cms plugin cache can be built/rebuilt.
	var v Version
	err := c.recordsdb.
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

// Hook executes the given cms plugin hook.
func (d *cms) Hook(tx *gorm.DB, hookID, payload string) error {
	log.Tracef("cms Hook: %v", hookID)

	return nil
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
