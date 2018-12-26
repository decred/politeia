package cockroachdb

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/jinzhu/gorm"
)

const (
	tableComments = "comments"
)

// TODO: create an index on token for quick lookups of a prop's comments
type Comment struct {
	Key         string `gorm:"primary_key"`       // Primary key (token+commentID)
	Token       string `gorm:"size:64;not null"`  // Censorship token
	ParentID    string `gorm:"not null"`          // Parent comment ID
	Comment     string `gorm:"not null"`          // Comment
	Signature   string `gorm:"size:128;not null"` // Client Signature of Token+ParentID+Comment
	PublicKey   string `gorm:"size:64;not null"`  // Pubkey used for Signature
	CommentID   string `gorm:"not null"`          // Comment ID
	Receipt     string `gorm:"not null"`          // Server signature of the client Signature
	Timestamp   int64  `gorm:"not null"`          // Received UNIX timestamp
	TotalVotes  uint64 `gorm:"not null"`          // Total number of up/down votes
	ResultVotes int64  `gorm:"not null"`          // Vote score
	Censored    bool   `gorm:"not null"`          // Has this comment been censored
}

func convertCommentFromDecredPlugin(c decredplugin.Comment) Comment {
	return Comment{
		Key:         c.Token + c.CommentID,
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  c.TotalVotes,
		ResultVotes: c.ResultVotes,
		Censored:    c.Censored,
	}
}

func convertCommentToDecredPlugin(c Comment) decredplugin.Comment {
	return decredplugin.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  c.TotalVotes,
		ResultVotes: c.ResultVotes,
		Censored:    c.Censored,
	}
}

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
