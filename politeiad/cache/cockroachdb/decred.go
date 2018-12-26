package cockroachdb

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/jinzhu/gorm"
)

const (
	tableComments = "comments"
)

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

// createDecredTables creates the cache tables needed by the decred plugin if
// they do not already exist.
//
// This function must be called within a transaction.
func (c *cockroachdb) createDecredTables(db *gorm.DB) error {
	if !db.HasTable(tableComments) {
		err := db.Table(tableComments).CreateTable(&Comment{}).Error
		if err != nil {
			return err
		}
	}
	return nil
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

func (c *cockroachdb) pluginNewComment(payload string) (string, error) {
	ncr, err := decredplugin.DecodeNewCommentReply([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeNewCommentReply: %v", err)
	}

	comment := convertCommentFromDecredPlugin(ncr.Comment)
	err = c.recorddb.Create(&comment).Error
	return "", err
}
