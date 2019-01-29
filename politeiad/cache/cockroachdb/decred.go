// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// Database table names
	tableComments       = "comments"
	tableCommentLikes   = "comment_likes"
	tableCastVotes      = "cast_votes"
	tableAuthorizeVotes = "authorize_votes"
	tableVoteOptions    = "vote_options"
	tableStartVotes     = "start_votes"
)

// decred implements the PluginDriver interface.
type decred struct {
	recordsdb *gorm.DB
	version   string
	settings  []cache.PluginSetting
}

func (d *decred) newComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred newComment")

	nc, err := decredplugin.DecodeNewComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	ncr, err := decredplugin.DecodeNewCommentReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	c := convertCommentFromDecred(*nc, *ncr)
	err = d.recordsdb.Create(&c).Error

	return replyPayload, err
}

func (d *decred) likeComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred likeComment")

	dlc, err := decredplugin.DecodeLikeComment([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	dlcr, err := decredplugin.DecodeLikeCommentReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	lc := convertLikeCommentFromDecred(*dlc, *dlcr)
	err = d.recordsdb.Create(&lc).Error

	return replyPayload, err
}

func (d *decred) censorComment(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred censorComment")

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

func (d *decred) getComment(payload string) (string, error) {
	log.Tracef("decred getComment")

	gc, err := decredplugin.DecodeGetComment([]byte(payload))
	if err != nil {
		return "", err
	}

	comment := Comment{
		Key: gc.Token + gc.CommentID,
	}
	err = d.recordsdb.Find(&comment).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	gcr := decredplugin.GetCommentReply{
		Comment: convertCommentToDecred(comment),
	}
	gcrb, err := decredplugin.EncodeGetCommentReply(gcr)
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

func (d *decred) getComments(payload string) (string, error) {
	log.Tracef("decred getComments")

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

func (d *decred) commentLikes(payload string) (string, error) {
	log.Tracef("decred commentLikes")

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

func (d *decred) proposalCommentsLikes(payload string) (string, error) {
	log.Tracef("decred proposalCommentsLikes")

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

func (d *decred) authorizeVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred authorizeVote")

	av, err := decredplugin.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// Run update in a transaction
	tx := d.recordsdb.Begin()

	// Delete authorize vote if one exists for this version
	err = tx.Where("key = ?", av.Token+avr.RecordVersion).
		Delete(AuthorizeVote{}).
		Error
	if err != nil {
		tx.Rollback()
		return "", fmt.Errorf("delete authorize vote: %v", err)
	}

	// Add new authorize vote
	a := AuthorizeVote{
		Key:       av.Token + avr.RecordVersion,
		Token:     av.Token,
		Version:   avr.RecordVersion,
		Action:    av.Action,
		Signature: av.Signature,
		PublicKey: av.PublicKey,
		Receipt:   avr.Receipt,
		Timestamp: avr.Timestamp,
	}
	err = tx.Create(&a).Error
	if err != nil {
		tx.Rollback()
		return "", err
	}

	// Commit transaction
	if tx.Commit().Error != nil {
		return "", fmt.Errorf("commit transaction failed: %v", err)
	}

	return replyPayload, nil
}

func (d *decred) startVote(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred startVote")

	sv, err := decredplugin.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	svr, err := decredplugin.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	s := convertStartVoteFromDecred(*sv, *svr)
	err = d.recordsdb.Create(&s).Error
	if err != nil {
		return "", err
	}

	return replyPayload, nil
}

func (d *decred) voteDetails(payload string) (string, error) {
	log.Tracef("decred voteDetails")

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
	err = d.recordsdb.
		Where("key = ?", vd.Token+r.Version).
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

func (d *decred) newBallot(cmdPayload, replyPayload string) (string, error) {
	log.Tracef("decred newBallot")

	b, err := decredplugin.DecodeBallot([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	br, err := decredplugin.DecodeBallotReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// There must be an equal number of votes and receipts
	if len(b.Votes) != len(br.Receipts) {
		return "", fmt.Errorf("votes and receipts do not match")
	}

	// Put receipts in a map for quick lookups
	receipts := make(map[string]string, len(b.Votes)) // [signature]receipt
	for _, v := range br.Receipts {
		receipts[v.ClientSignature] = v.Signature
	}

	// Add votes to database
	for _, v := range b.Votes {
		cv := CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   receipts[v.Signature],
		}
		err = d.recordsdb.Create(&cv).Error
		if err != nil {
			return "", err
		}
	}

	return replyPayload, nil
}

func (d *decred) proposalVotes(payload string) (string, error) {
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
	if err != nil {
		return "", fmt.Errorf("start vote lookup failed: %v", err)
	}

	// Lookup all cast votes
	var cv []CastVote
	err = d.recordsdb.
		Where("token = ?", vr.Token).
		Find(&cv).
		Error
	if err != nil {
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

func (d *decred) inventory() (string, error) {
	log.Tracef("inventory")

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

// createDecredTables creates the cache tables needed by the decred plugin if
// they do not already exist.
//
// This function must be called within a transaction.
func createDecredTables(tx *gorm.DB) error {
	log.Tracef("createDecredTables")
	// TODO insert version record into versions table

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

	return nil
}

func (d *decred) Setup() error {
	log.Tracef("decred Setup")

	tx := d.recordsdb.Begin()
	err := createDecredTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (d *decred) Build(payload string) error {
	log.Tracef("decred Build")

	// Drop decred plugin tables from the cache
	err := d.recordsdb.DropTableIfExists(tableComments,
		tableCommentLikes, tableCastVotes, tableAuthorizeVotes,
		tableVoteOptions, tableStartVotes).Error
	if err != nil {
		return err
	}

	err = d.Setup()
	if err != nil {
		return err
	}

	// TODO: build decred plugin cache

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
		return d.authorizeVote(cmdPayload, replyPayload)
	case decredplugin.CmdStartVote:
		return d.startVote(cmdPayload, replyPayload)
	case decredplugin.CmdVoteDetails:
		return d.voteDetails(cmdPayload)
	case decredplugin.CmdBallot:
		return d.newBallot(cmdPayload, replyPayload)
	case decredplugin.CmdBestBlock:
		return "", nil
	case decredplugin.CmdNewComment:
		return d.newComment(cmdPayload, replyPayload)
	case decredplugin.CmdLikeComment:
		return d.likeComment(cmdPayload, replyPayload)
	case decredplugin.CmdCensorComment:
		return d.censorComment(cmdPayload, replyPayload)
	case decredplugin.CmdGetComment:
		return d.getComment(cmdPayload)
	case decredplugin.CmdGetComments:
		return d.getComments(cmdPayload)
	case decredplugin.CmdProposalVotes:
		return d.proposalVotes(cmdPayload)
	case decredplugin.CmdCommentLikes:
		return d.commentLikes(cmdPayload)
	case decredplugin.CmdProposalCommentsLikes:
		return d.proposalCommentsLikes(cmdPayload)
	case decredplugin.CmdInventory:
		return d.inventory()
	}

	return "", cache.ErrInvalidPluginCmd
}

func newDecredPlugin(db *gorm.DB, p cache.Plugin) *decred {
	log.Tracef("newDecredPlugin: %v", p.Version)
	return &decred{
		recordsdb: db,
		version:   p.Version,
		settings:  p.Settings,
	}
}
