package cockroachdb

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	tableComments     = "comments"
	tableCommentLikes = "comment_likes"
)

// createDecredTables creates the cache tables needed by the decred plugin if
// they do not already exist.
//
// This function must be called within a transaction.
func createDecredTables(db *gorm.DB) error {
	log.Tracef("createDecredTables")

	if !db.HasTable(tableComments) {
		err := db.Table(tableComments).CreateTable(&Comment{}).Error
		if err != nil {
			return err
		}
	}
	if !db.HasTable(tableCommentLikes) {
		err := db.Table(tableCommentLikes).CreateTable(&LikeComment{}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *cockroachdb) pluginNewComment(reqPayload, resPayload string) (string, error) {
	log.Tracef("pluginNewComment")

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(resPayload))
	if err != nil {
		return "", fmt.Errorf("DecodeNewCommentReply: %v", err)
	}

	comment := convertCommentFromDecredPlugin(ncr.Comment)
	err = c.recorddb.Create(&comment).Error
	return resPayload, err
}

func (c *cockroachdb) pluginGetComment(payload string) (string, error) {
	log.Tracef("pluginGetComment")

	gc, err := decredplugin.DecodeGetComment([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetComment: %v", err)
	}

	comment := Comment{
		Key: gc.Token + gc.CommentID,
	}
	err = c.recorddb.Find(&comment).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = cache.ErrRecordNotFound
		}
		return "", err
	}

	gcr := decredplugin.GetCommentReply{
		Comment: convertCommentToDecredPlugin(comment),
	}
	gcrb, err := decredplugin.EncodeGetCommentReply(gcr)
	if err != nil {
		return "", err
	}
	return string(gcrb), nil
}

func (c *cockroachdb) pluginLikeComment(reqPayload, resPayload string) (string, error) {
	log.Tracef("pluginLikeComment")

	dlc, err := decredplugin.DecodeLikeComment([]byte(reqPayload))
	if err != nil {
		return "", fmt.Errorf("DecodeLikeComment: %v", err)
	}

	dlcr, err := decredplugin.DecodeLikeCommentReply([]byte(resPayload))
	if err != nil {
		return "", fmt.Errorf("DecodeLikeCommentReply: %v", err)
	}

	lc := convertLikeCommentFromDecredPlugin(*dlc, *dlcr)
	err = c.recorddb.Table(tableCommentLikes).Create(&lc).Error
	return resPayload, err
}

func (c *cockroachdb) pluginCensorComment(reqPayload, resPayload string) (string, error) {
	log.Tracef("pluginCensorComment")

	cc, err := decredplugin.DecodeCensorComment([]byte(reqPayload))
	if err != nil {
		return "", fmt.Errorf("DecredCensorComment: %v", err)
	}

	comment := Comment{
		Key: cc.Token + cc.CommentID,
	}
	err = c.recorddb.Model(&comment).
		Updates(map[string]interface{}{
			"censored": true,
		}).Error
	if err != nil {
		return "", err
	}

	return resPayload, nil
}
