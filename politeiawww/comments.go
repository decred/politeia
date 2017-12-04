package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

type CommentActionT int

const (
	defaultCommentJournalDir = "comments"
	defaultCommentVersion    = uint64(1)

	CommentActionInvalid CommentActionT = 0 // Invalid action
	CommentActionAdd     CommentActionT = 1 // Add comment
	CommentActionDelete  CommentActionT = 2 // Delete comment
)

// BackendComment wraps www.Comment into an internal usable structure.
type BackendComment struct {
	// www additional fields
	Version uint64
	Action  CommentActionT

	// Meta-data
	Timestamp int64  // Received UNIX timestamp
	UserID    string // Originating user
	CommentID string // Comment ID

	// Data
	Token     string // Censorship token
	ParentID  string // Parent comment ID
	Comment   string // Comment
	Signature string // Signature of Token+ParentID+Comment
}

// backendCommentToComment converts BackendComment to www.Comment.
func backendCommentToComment(bec BackendComment) www.Comment {
	return www.Comment{
		Timestamp: bec.Timestamp,
		UserID:    bec.UserID,
		CommentID: bec.CommentID,
		Token:     bec.Token,
		ParentID:  bec.ParentID,
		Comment:   bec.Comment,
		Signature: bec.Signature,
	}
}

// backendCommentToComment converts BackendComment to www.Comment.
func wwwCommentToBackendComment(www BackendComment) BackendComment {
	return BackendComment{
		Timestamp: www.Timestamp,
		UserID:    www.UserID,
		CommentID: www.CommentID,
		Token:     www.Token,
		ParentID:  www.ParentID,
		Comment:   www.Comment,
		Signature: www.Signature,
	}
}

// initComment initializes the comment map for the given token.  This call must
// be called with the lock held.
func (b *backend) initComment(token string) {
	if _, ok := b.comments[token]; ok {
		return
	}
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

	// validations
	// XXX this needs to be more rigorous
	if err := validateComment(c); err != nil {
		return nil, err
	}

	// Journal comment
	comment := BackendComment{
		Version:   defaultCommentVersion,
		Action:    CommentActionAdd,
		Timestamp: time.Now().Unix(),
		UserID:    strconv.FormatUint(userID, 10),
		CommentID: strconv.FormatUint(b.commentID, 10),
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		Signature: c.Signature,
	}
	cb, err := json.Marshal(comment)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path.Join(b.commentJournalDir, c.Token),
		os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", cb)

	// Store comment in memory for quick lookup
	b.comments[c.Token][b.commentID] = comment
	cr := www.NewCommentReply{
		CommentID: comment.CommentID,
	}
	b.commentID++

	return &cr, nil
}

// replayCommentJournal reads the comments journal and recreates the internal
// memory map.  Not all failures are considered fatal.  It is better to load
// some comments instead of none.
// This call must be called with the lock held.
func (b *backend) replayCommentJournal(token string) error {
	// Replay journal
	f, err := os.Open(token)
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

		// Verify comment version
		if c.Version != defaultCommentVersion {
			log.Errorf("unsupported comment version: got %v "+
				"wanted %v", c.Version, defaultCommentVersion)
			continue
		}

		cid, err := strconv.ParseUint(c.CommentID, 10, 64)
		if err != nil {
			log.Errorf("invalid CommentID %v", err)
			continue
		}

		// Add to memory cache
		if _, ok := b.comments[c.Token]; !ok {
			b.comments[c.Token] = make(map[uint64]BackendComment)
		}

		switch c.Action {
		case CommentActionAdd:
			b.comments[c.Token][cid] = c
		case CommentActionDelete:
			delete(b.comments[c.Token], cid)
		default:
			log.Errorf("invalid comment action: %v token %v "+
				"comment id %v", c.Action, c.Token, c.CommentID)
			// fallthrough
		}

		// See if this is the last comment
		if cid > b.commentID {
			b.commentID = cid
		}
	}

	return nil
}

// replayCommentJournals replays all comment journals into the memory cache.
func (b *backend) replayCommentJournals() error {
	fi, err := ioutil.ReadDir(b.commentJournalDir)
	if err != nil {
		return err
	}

	for _, v := range fi {
		filename := v.Name()
		_, err = util.ConvertStringToken(filename)
		if err != nil {
			log.Tracef("replayCommentJournals: skipping %v",
				filename)
			continue
		}
		log.Tracef("replayCommentJournals: %v", filename)
		err = b.replayCommentJournal(filepath.Join(b.commentJournalDir,
			filename))
		if err != nil {
			// log but ignore errors
			log.Errorf("replayCommentJournals: %v", err)
		}
	}

	return nil
}

// flushCommentJournal flushes all comments to politeiad. For now this uses the
// large hammer approach of always flushing all comments.
func (b *backend) flushCommentJournals() error {
	fi, err := ioutil.ReadDir(b.commentJournalDir)
	if err != nil {
		return err
	}

	for _, v := range fi {
		filename := v.Name()
		_, err = util.ConvertStringToken(filename)
		if err != nil {
			log.Tracef("flushCommentJournals: skipping %v",
				filename)
			continue
		}

		log.Tracef("flushCommentJournals: %v", filename)

		md, err := ioutil.ReadFile(filepath.Join(b.commentJournalDir,
			filename))
		if err != nil {
			// log but ignore errors
			log.Errorf("flushCommentJournals: %v", err)
			continue

		}

		// Create update command
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			// Should not happen so bail
			return err
		}
		upd := pd.UpdateVettedMetadata{
			Challenge: hex.EncodeToString(challenge),
			Token:     filename,
			MDOverwrite: []pd.MetadataStream{{
				ID:      mdStreamComments,
				Payload: string(md),
			}},
		}

		responseBody, err := b.makeRequest(http.MethodPost,
			pd.UpdateVettedMetadataRoute, upd)
		if err != nil {
			e, ok := err.(www.PDError)
			if !ok {
				log.Errorf("flushCommentJournals: update %v", err)
				continue
			}
			log.Errorf("flushCommentJournals: update %v",
				pd.ErrorStatus[pd.ErrorStatusT(e.ErrorReply.ErrorCode)])
			continue
		}

		var uur pd.UpdateUnvettedReply
		err = json.Unmarshal(responseBody, &uur)
		if err != nil {
			log.Errorf("flushCommentJournals: unmarshal %v", err)
			continue
		}

		err = util.VerifyChallenge(b.cfg.Identity, challenge,
			uur.Response)
		if err != nil {
			log.Errorf("flushCommentJournals: verify %v", err)
			continue
		}
	}

	return nil
}

func validateComment(c www.NewComment) error {
	// max length
	if len(c.Comment) > www.PolicyMaxCommentLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		}
	}
	// validate token
	_, err := util.ConvertStringToken(c.Token)
	return err
}
