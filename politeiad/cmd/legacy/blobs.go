package main

import (
	"encoding/hex"
	"encoding/json"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	tv "github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiawww/client"
)

// Ticketvote blobs

// saveVotesBlobs saves all cast vote blobs into tstore.
func (l *legacy) saveVotesBlobs(votes []*tv.CastVoteDetails, newToken []byte) error {

	for _, vote := range votes {
		// Save cast vote details to tstore.
		err := l.blobSaveCastVoteDetails(*vote, newToken)
		if err != nil {
			return err
		}

		// Save vote collider blob to tstore.
		err = l.blobSaveVoteCollider(voteCollider{
			Token:  hex.EncodeToString(newToken),
			Ticket: vote.Ticket,
		}, newToken)
		if err != nil {
			return err
		}
	}

	return nil
}

func (l *legacy) blobSaveCastVoteDetails(cdv tv.CastVoteDetails, newToken []byte) error {
	// Verify cast vote details signature.
	err := client.CastVoteDetailsVerify(convertCastVoteDetailsToV1(cdv), serverPubkey)
	if err != nil {
		return err
	}

	data, err := json.Marshal(cdv)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-castvote-v1",
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)

	err = l.tstore.BlobSave(newToken, be)
	if err != nil && err.Error() == "duplicate payload" {
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveAuthDetails(authDetails tv.AuthDetails, newToken []byte) error {
	// Verify auth details signature.
	err := client.AuthDetailsVerify(convertAuthDetailsToV1(authDetails),
		serverPubkey)
	if err != nil {
		return err
	}

	data, err := json.Marshal(authDetails)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-auth-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveVoteDetails(voteDetails tv.VoteDetails, newToken []byte) error {
	data, err := json.Marshal(voteDetails)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-vote-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveVoteCollider(vc voteCollider, newToken []byte) error {
	data, err := json.Marshal(vc)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-vcollider-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveStartRunoff(srr startRunoffRecord, newToken []byte) error {
	data, err := json.Marshal(srr)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: tv.PluginID + "-startrunoff-v1",
		})
	if err != nil {
		return err
	}

	be := store.NewBlobEntry(hint, data)
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

// Comments Blobs

// saveCommentsBlobs saves all comment blobs from a record into tstore.
func (l *legacy) saveCommentsBlobs(comments parsedComments, newToken []byte) error {
	// Save add comments blob to tstore.
	for _, add := range comments.Adds {
		err := l.blobSaveCommentAdd(add, newToken)
		if err != nil {
			return err
		}
	}

	// Save del comments blob to tstore.
	for _, del := range comments.Dels {
		err := l.blobSaveCommentDel(del, newToken)
		if err != nil {
			return err
		}
	}

	// Save vote comments blob to tstore.
	for _, vote := range comments.Votes {
		err := l.blobSaveCommentVote(vote, newToken)
		if err != nil {
			return err
		}
	}

	return nil
}

func (l *legacy) blobSaveCommentAdd(add comments.CommentAdd, newToken []byte) error {
	// Create blob entry.
	data, err := json.Marshal(add)
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

	// Save to tstore.
	err = l.tstore.BlobSave(newToken, be)
	if err != nil && err.Error() == "duplicate payload" {
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveCommentDel(del comments.CommentDel, newToken []byte) error {
	// Create blob entry.
	data, err := json.Marshal(del)
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

	// Save to tstore.
	err = l.tstore.BlobSave(newToken, be)
	if err != nil {
		return err
	}

	return nil
}

func (l *legacy) blobSaveCommentVote(vote comments.CommentVote, newToken []byte) error {
	// Create blob entry.
	data, err := json.Marshal(vote)
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

	// Save to tstore.
	err = l.tstore.BlobSave(newToken, be)
	if err != nil && err.Error() == "duplicate payload" {
		return nil
	}
	if err != nil {
		return err
	}

	return nil
}
