// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// decredVersion is the version of the cache implementation of
	// decred plugin. This may differ from the decredplugin package
	// version.
	decredVersion = "1"

	// Decred plugin table names
	tableComments       = "comments"
	tableCommentLikes   = "comment_likes"
	tableCastVotes      = "cast_votes"
	tableAuthorizeVotes = "authorize_votes"
	tableVoteOptions    = "vote_options"
	tableStartVotes     = "start_votes"
)

// decred implements the PluginDriver interface.
type decred struct {
	recordsdb *gorm.DB              // Database context
	version   string                // Version of decred cache plugin
	settings  []cache.PluginSetting // Plugin settings
}

// newComment inserts a Comment record into the database.  This function has a
// database parameter so that it can be called inside of a transaction when
// required.
func (d *decred) newComment(db *gorm.DB, c Comment) error {
	return db.Create(&c).Error
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
	err = d.newComment(d.recordsdb, c)

	return replyPayload, err
}

// newLikeComment inserts a LikeComment record into the database.  This
// function has a database parameter so that it can be called inside of a
// transaction when required.
func (d *decred) newLikeComment(db *gorm.DB, lc LikeComment) error {
	return db.Create(&lc).Error
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
	err = d.newLikeComment(d.recordsdb, lc)

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

// cmdGetComment retreives the passed in comment from the database.
func (d *decred) cmdGetComment(payload string) (string, error) {
	log.Tracef("decred cmdGetComment")

	gc, err := decredplugin.DecodeGetComment([]byte(payload))
	if err != nil {
		return "", err
	}

	c := Comment{
		Key: gc.Token + gc.CommentID,
	}
	err = d.recordsdb.Find(&c).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	gcr := decredplugin.GetCommentReply{
		Comment: convertCommentToDecred(c),
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

// newAuthorizeVote creates an AuthorizeVote record and inserts it into the
// database.  If a previous AuthorizeVote record exists for the passed in
// proposal and version, it will be deleted before the new AuthorizeVote record
// is inserted.
//
// This function must be called within a transaction.
func (d *decred) newAuthorizeVote(tx *gorm.DB, av AuthorizeVote) error {
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

	v, err := strconv.ParseUint(avr.RecordVersion, 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse version '%v' failed: %v",
			avr.RecordVersion, err)
	}

	// Run update in a transaction
	a := convertAuthorizeVoteFromDecred(*av, *avr, v)
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
func (d *decred) newStartVote(db *gorm.DB, sv StartVote) error {
	return db.Create(&sv).Error
}

// cmdStartVote creates a StartVote record using the passed in payloads and
// inserts it into the database.
func (d *decred) cmdStartVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdStartVote")

	sv, err := decredplugin.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := decredplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	s := convertStartVoteFromDecred(*sv, *svr)
	err = d.newStartVote(d.recordsdb, s)
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
	dav := convertAuthorizeVoteToDecred(av)
	dsv, dsvr := convertStartVoteToDecred(sv)
	vdr := decredplugin.VoteDetailsReply{
		AuthorizeVote:  dav,
		StartVote:      dsv,
		StartVoteReply: dsvr,
	}
	vdrb, err := decredplugin.EncodeVoteDetailsReply(vdr)
	if err != nil {
		return "", err
	}

	return string(vdrb), nil
}

// newCastVote inserts a CastVote record into the database.  This function has
// a database parameter so that it can be called inside of a transaction when
// required.
func (d *decred) newCastVote(db *gorm.DB, cv CastVote) error {
	return db.Create(&cv).Error
}

// cmdNewBallot creates CastVote records using the passed in payloads and
// inserts them into the database.
func (d *decred) cmdNewBallot(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred cmdNewBallot")

	b, err := decredplugin.DecodeBallot([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	// Add votes to database
	tx := d.recordsdb.Begin()
	for _, v := range b.Votes {
		cv := convertCastVoteFromDecred(v)
		err = d.newCastVote(tx, cv)
		if err != nil {
			tx.Rollback()
			return "", err
		}
	}

	err = tx.Commit().Error
	if err != nil {
		return "", fmt.Errorf("commit transaction failed: %v", err)
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
	dsv, _ := convertStartVoteToDecred(sv)
	dcv := make([]decredplugin.CastVote, 0, len(cv))
	for _, v := range cv {
		dcv = append(dcv, convertCastVoteToDecred(v))
	}

	vrr := decredplugin.VoteResultsReply{
		StartVote: dsv,
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
	case decredplugin.CmdProposalVotes:
		return d.cmdProposalVotes(cmdPayload)
	case decredplugin.CmdCommentLikes:
		return d.cmdCommentLikes(cmdPayload)
	case decredplugin.CmdProposalCommentsLikes:
		return d.cmdProposalCommentsLikes(cmdPayload)
	case decredplugin.CmdInventory:
		return d.cmdInventory()
	}

	return "", cache.ErrInvalidPluginCmd
}

// createDecredTables creates the cache tables needed by the decred plugin if
// they do not already exist. A decred plugin version record is inserted into
// the database during table creation.
//
// This function must be called within a transaction.
func createDecredTables(tx *gorm.DB) error {
	log.Tracef("createDecredTables")

	// Create decred plugin tables
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

	// Check if a decred version record exists. Insert one
	// if no version record is found.
	if !tx.HasTable(tableVersions) {
		// This should never happen
		return fmt.Errorf("versions table not found")
	}

	var v Version
	err := tx.Where("id = ?", decredplugin.ID).
		Find(&v).
		Error
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

// build the decred plugin cache using the passed in inventory.
//
// This function must be called within a transaction.
func (d *decred) build(tx *gorm.DB, ir *decredplugin.InventoryReply) error {
	log.Tracef("decred build")

	// Create the database tables
	err := createDecredTables(tx)
	if err != nil {
		return fmt.Errorf("createDecredTables: %v", err)
	}

	// Build comments cache. Comments that have been censored will
	// be marked as censored.
	for _, v := range ir.Comments {
		c := convertCommentFromDecred(v)
		err := d.newComment(tx, c)
		if err != nil {
			log.Debugf("newComment failed on '%v'", c)
			return fmt.Errorf("newComment: %v", err)
		}
	}

	// Build like comments cache
	for _, v := range ir.LikeComments {
		lc := convertLikeCommentFromDecred(v)
		err := d.newLikeComment(tx, lc)
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
	for _, v := range ir.AuthorizeVotes {
		r, ok := avr[v.Receipt]
		if !ok {
			return fmt.Errorf("AuthorizeVoteReply not found %v", v.Token)
		}

		rv, err := strconv.ParseUint(r.RecordVersion, 10, 64)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", r)
			return fmt.Errorf("parse version '%v' failed: %v",
				r.RecordVersion, err)
		}

		av := convertAuthorizeVoteFromDecred(v, r, rv)
		err = d.newAuthorizeVote(tx, av)
		if err != nil {
			log.Debugf("newAuthorizeVote failed on '%v'", av)
			return fmt.Errorf("newAuthorizeVote: %v", err)
		}
	}

	// Build start vote cache
	for _, v := range ir.StartVoteTuples {
		sv := convertStartVoteFromDecred(v.StartVote, v.StartVoteReply)
		err := d.newStartVote(tx, sv)
		if err != nil {
			log.Debugf("newStartVote failed on '%v'", sv)
			return fmt.Errorf("newStartVote: %v", err)
		}
	}

	// Build cast vote cache
	for _, v := range ir.CastVotes {
		cv := convertCastVoteFromDecred(v)
		err := d.newCastVote(tx, cv)
		if err != nil {
			log.Debugf("newCastVote failed on '%v'", cv)
			return fmt.Errorf("newCastVote: %v", err)
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

	// Drop all decred plugin tables
	err = d.recordsdb.DropTableIfExists(tableComments,
		tableCommentLikes, tableCastVotes, tableAuthorizeVotes,
		tableVoteOptions, tableStartVotes).Error
	if err != nil {
		return fmt.Errorf("drop decred tables failed: %v", err)
	}

	// Build the decred plugin cache from scratch
	tx := d.recordsdb.Begin()
	err = d.build(tx, ir)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// Setup creates the decred plugin tables if they do not already exist.  A
// decred plugin version record is inserted into the database during table
// creation.
func (d *decred) Setup() error {
	tx := d.recordsdb.Begin()
	err := createDecredTables(tx)
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
	// Sanity check. Ensure version table exists.
	if !d.recordsdb.HasTable(tableVersions) {
		return fmt.Errorf("versions table not found")
	}

	// Lookup version record
	var v Version
	err := d.recordsdb.
		Where("id = ?", decredplugin.ID).
		Find(&v).
		Error
	if err == gorm.ErrRecordNotFound {
		// A version record not being found indicates that the
		// decred plugin cache has not been built yet. Return a
		// ErrWrongPluginVersion error so that the cache will be
		// built.
		return cache.ErrWrongPluginVersion
	} else if err != nil {
		return err
	}

	// Ensure we're using the correct version
	if v.Version != decredVersion {
		return cache.ErrWrongPluginVersion
	}

	return nil
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
