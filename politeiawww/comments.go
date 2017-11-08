package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	www "github.com/decred/politeia/politeiawww/api/v1"
)

const (
	defaultCommentJournalDir  = "comments"
	defaultCommentJournalFile = "journal.json"
)

// BackendComment wraps www.Comment into an internal usable structure.
type BackendComment struct {
	CommentID uint64
	UserID    uint64
	ParentID  uint64
	Timestamp int64
	Token     string
	Comment   string

	// www additional fields
	Flushed bool // Set to true when it has been sent to politeaid
}

// backendCommentToComment converts BackendComment to www.Comment.
func backendCommentToComment(bec BackendComment) www.Comment {
	return www.Comment{
		CommentID: bec.CommentID,
		UserID:    bec.UserID,
		ParentID:  bec.ParentID,
		Timestamp: bec.Timestamp,
		Token:     bec.Token,
		Comment:   bec.Comment,
	}
}

// initComment initializes the comment map for the given token.  This call must
// be called with the lock held.
func (b *backend) initComment(token string) {
	b.comments[token] = make(map[uint64]BackendComment)
}

// getComments returns all comments for given proposal token.  Note that the
// comments are not sorted.
// This call must be called WITHOUT the lock held.
func (b *backend) getComments(token string) (*www.GetCommentsReply, error) {
	b.RLock()
	defer b.RUnlock()

	c, ok := b.comments[token]
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	gcr := &www.GetCommentsReply{
		Comments: make([]www.Comment, 0, len(c)),
	}
	for _, v := range c {
		gcr.Comments = append(gcr.Comments,
			backendCommentToComment(v))
	}

	return gcr, nil
}

// addComment journals and adds comment to memory map.
// This call must be called with the lock held.
func (b *backend) addComment(c www.NewComment, userID uint64) (*www.NewCommentReply, error) {
	// Journal comment
	comment := BackendComment{
		CommentID: b.commentID,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
	}
	cb, err := json.Marshal(comment)
	if err != nil {
		return nil, fmt.Errorf("Marshal comment: %v", err)
	}
	f, err := os.OpenFile(b.commentJournalFile,
		os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", cb)

	// Store comment in memory for quick lookup
	b.comments[c.Token][b.commentID] = comment
	cr := www.NewCommentReply{
		CommentID: b.commentID,
	}
	b.commentID++

	return &cr, nil
}

// replayCommentJournal reads the comments journal and recreates the internal
// memory map.
// This call must be called with the lock held.
func (b *backend) replayCommentJournal() error {
	// Replay journal
	f, err := os.Open(b.commentJournalFile)
	if err != nil {
		// See if there is something to do with the journal.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	for {
		var c BackendComment
		if err := d.Decode(&c); err == io.EOF {
			break // done decoding file
		} else if err != nil {
			return err
		}
		// Add to memory cache
		if _, ok := b.comments[c.Token]; !ok {
			b.comments[c.Token] = make(map[uint64]BackendComment)
		}
		b.comments[c.Token][c.CommentID] = c

		// See if this is the last comment
		if c.CommentID > b.commentID {
			b.commentID = c.CommentID
		}
	}

	return nil
}
