// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

/*
func convertCommentVoteFromPlugin(v comments.VoteT) piv1.CommentVoteT {
	switch v {
	case comments.VoteDownvote:
		return piv1.CommentVoteDownvote
	case comments.VoteUpvote:
		return piv1.CommentVoteUpvote
	}
	return piv1.CommentVoteInvalid
}

func convertProofFromCommentsPlugin(p comments.Proof) cmv1.Proof {
	return cmv1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampFromCommentsPlugin(t comments.Timestamp) cmv1.Timestamp {
	proofs := make([]cmv1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofFromCommentsPlugin(v))
	}
	return cmv1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

// commentPopulateUser populates the provided comment with user data that is
// not stored in politeiad.
func commentPopulateUser(c piv1.Comment, u user.User) cmv1.Comment {
	c.Username = u.Username
	return c
}

func (c *Comments) processCommentTimestamps(ctx context.Context, t cmv1.Timestamps, isAdmin bool) (*cmv1.TimestampsReply, error) {
	log.Tracef("processCommentTimestamps: %v %v %v",
		t.State, t.Token, t.CommentIDs)

	// Get timestamps
	ct := comments.Timestamps{
		CommentIDs:   t.CommentIDs,
		IncludeVotes: false,
	}
	ctr, err := p.commentTimestamps(ctx, ct)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	comments := make(map[uint32][]cmv1.Timestamp, len(ctr.Comments))
	for commentID, timestamps := range ctr.Comments {
		ts := make([]cmv1.Timestamp, 0, len(timestamps))
		for _, v := range timestamps {
			// Strip unvetted data blobs if the user is not an admin
			if t.State == cmv1.RecordStateUnvetted && !isAdmin {
				v.Data = ""
			}
			ts = append(ts, convertTimestampFromCommentsPlugin(v))
		}
		comments[commentID] = ts
	}

	return &cmv1.TimestampsReply{
		Comments: comments,
	}, nil
}


func (c *Comments) handleCommentTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentTimestamps")

	var t cmv1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithCommentsError(w, r, "handleCommentTimestamps: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.GetSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithCommentsError(w, r,
			"handleCommentTimestamps: GetSessionUser: %v", err)
		return
	}

	isAdmin := usr != nil && usr.Admin
	tr, err := p.processCommentTimestamps(r.Context(), t, isAdmin)
	if err != nil {
		respondWithCommentsError(w, r,
			"handleCommentTimestamps: processCommentTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tr)
}
*/
