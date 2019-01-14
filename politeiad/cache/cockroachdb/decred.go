package cockroachdb

import (
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	// Database table names
	tableComments     = "comments"
	tableCommentLikes = "comment_likes"
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

func (d *decred) inventory() (string, error) {
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

	// Get all like comments
	var cl []LikeComment
	err = d.recordsdb.Find(&cl).Error
	if err != nil {
		return "", err
	}

	dcl := make([]decredplugin.LikeComment, 0, len(cl))
	for _, v := range cl {
		dcl = append(dcl, convertLikeCommentToDecred(v))
	}

	// Prepare inventory reply
	ir := decredplugin.InventoryReply{
		Comments:     dc,
		CommentLikes: dcl,
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
		tableCommentLikes).Error
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
		return "", nil
	case decredplugin.CmdStartVote:
		return "", nil
	case decredplugin.CmdBallot:
		return "", nil
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
		return "", nil
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
