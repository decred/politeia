package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
)

// convertCommentsJournal walks through the legacy comments journal converting
// them to the appropriate plugin payloads for the tstore backend.
func (l *legacyImport) convertCommentsJournal(path string, newToken []byte) error {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(fh)

	// Initialize comments cache
	l.Lock()
	l.comments[hex.EncodeToString(newToken)] = make(map[string]decredplugin.Comment)
	l.Unlock()

	for i := 0; s.Scan(); i++ {
		// json text from reading each journal line
		// fmt.Println(s.Text())

		ss := bytes.NewReader([]byte(s.Text()))
		d := json.NewDecoder(ss)

		var action gitbe.JournalAction
		err := d.Decode(&action)
		if err != nil {
			return err
		}

		switch action.Action {

		case "add":
			var c decredplugin.Comment
			err = d.Decode(&c)
			if err != nil {
				return fmt.Errorf("comment journal add: %v", err)
			}
			err = l.blobSaveCommentAdd(c, newToken)
			if err != nil {
				return err
			}

			l.Lock()
			l.comments[hex.EncodeToString(newToken)][c.CommentID] = c
			l.Unlock()

		case "del":
			var cc decredplugin.CensorComment
			err = d.Decode(&cc)
			if err != nil {
				return fmt.Errorf("comment journal censor: %v", err)
			}

			l.RLock()
			parentID := l.comments[hex.EncodeToString(newToken)][cc.CommentID].ParentID
			l.RUnlock()

			err = l.blobSaveCommentDel(cc, newToken, parentID)
			if err != nil {
				return fmt.Errorf("comment journal del: %v", err)
			}

		case "addlike":
			var lc likeCommentV1
			err = d.Decode(&lc)
			if err != nil {
				return fmt.Errorf("comment journal addlike: %v", err)
			}
			fmt.Println("\n\n like comment payload from journal")
			fmt.Println(lc)
			fmt.Println("")

			err = l.blobSaveCommentLike(lc, newToken)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid action: %v",
				action.Action)
		}
	}

	return nil
}

func (l *legacyImport) blobSaveCommentAdd(c decredplugin.Comment, newToken []byte) error {
	fmt.Println("\n comments: Saving CommentAdd blob ...")

	// Get user id from pubkey
	usr, err := l.fetchUserByPubKey(c.PublicKey)
	if err != nil {
		return err
	}

	// Parse IDs
	pid, err := strconv.Atoi(c.ParentID)
	if err != nil {
		return err
	}
	cid, err := strconv.Atoi(c.CommentID)
	if err != nil {
		return err
	}

	// Create comment add blob entry
	cn := &comments.CommentAdd{
		UserID:    usr.ID,
		State:     comments.RecordStateVetted,
		Token:     hex.EncodeToString(newToken),
		ParentID:  uint32(pid),
		Comment:   c.Comment,
		PublicKey: c.PublicKey,
		Signature: c.Signature,
		CommentID: uint32(cid),
		Version:   1,
		Timestamp: c.Timestamp,
		Receipt:   c.Receipt,
	}
	data, err := json.Marshal(cn)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: comments.PluginID + "-add-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	fmt.Println(" comments: Saved!")

	return nil
}

func (l *legacyImport) blobSaveCommentDel(cc decredplugin.CensorComment, newToken []byte, parentID string) error {
	fmt.Println("\n comments: Saving CommentDel blob ...")

	// Get user ID from pubkey
	usr, err := l.fetchUserByPubKey(cc.PublicKey)
	if err != nil {
		return err
	}

	// Parse parent ID
	pid, err := strconv.Atoi(parentID)
	if err != nil {
		return err
	}

	// Parse comment ID
	cid, err := strconv.Atoi(cc.CommentID)
	if err != nil {
		return err
	}

	// Create comment del blob entry
	cd := &comments.CommentDel{
		Token:     hex.EncodeToString(newToken),
		State:     comments.RecordStateVetted,
		CommentID: uint32(cid),
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,

		ParentID:  uint32(pid),
		UserID:    usr.ID,
		Timestamp: cc.Timestamp,
		Receipt:   cc.Receipt,
	}
	data, err := json.Marshal(cd)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: comments.PluginID + "-del-v1",
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	fmt.Println(" comments: Saved!")

	return nil
}

func (l *legacyImport) blobSaveCommentLike(lc likeCommentV1, newToken []byte) error {
	fmt.Println("\n comments: Saving CommentLike blob ...")

	// Get user ID from pubkey
	usr, err := l.fetchUserByPubKey(lc.PublicKey)
	if err != nil {
		return err
	}

	// Parse comment ID
	cid, err := strconv.Atoi(lc.CommentID)
	if err != nil {
		return err
	}

	// Parse comment vote
	var vote comments.VoteT
	switch {
	case lc.Action == "1":
		vote = comments.VoteUpvote
	case lc.Action == "-1":
		vote = comments.VoteDownvote
	default:
		return fmt.Errorf("invalid comment vote code")
	}

	// Create comment vote blob entry
	c := &comments.CommentVote{
		UserID:    usr.ID,
		State:     comments.RecordStateVetted,
		Token:     hex.EncodeToString(newToken),
		CommentID: uint32(cid),
		Vote:      vote,
		PublicKey: lc.PublicKey,
		Signature: lc.Signature,
		Timestamp: lc.Timestamp,
		Receipt:   lc.Receipt,
	}

	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: comments.PluginID + "-vote-v1",
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil && err.Error() == "duplicate blob" {
		fmt.Println(" comments: Duplicate blob, skip entry!")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Println(" comments: Saved!")

	return nil
}
