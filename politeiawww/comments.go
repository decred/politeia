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

func convertCommentVoteDetailsFromPlugin(cv []comments.CommentVote) []piv1.CommentVoteDetails {
	c := make([]piv1.CommentVoteDetails, 0, len(cv))
	for _, v := range cv {
		c = append(c, piv1.CommentVoteDetails{
			UserID:    v.UserID,
			Token:     v.Token,
			CommentID: v.CommentID,
			Vote:      convertCommentVoteFromPlugin(v.Vote),
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return c
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

func (c *Comments) processCommentCensor(ctx context.Context, cc cmv1.CommentCensor, usr user.User) (*cmv1.CommentCensorReply, error) {
	log.Tracef("processCommentCensor: %v %v", cc.Token, cc.CommentID)

	// Sanity check
	if !usr.Admin {
		return nil, fmt.Errorf("not an admin")
	}

	// Verify user signed with their active identity
	if usr.PublicKey() != cc.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	d := comments.Del{
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		PublicKey: cc.PublicKey,
		Signature: cc.Signature,
	}
	// TODO
	_ = d
	var dr comments.DelReply

	// Prepare reply
	c := convertCommentFromPlugin(dr.Comment)
	c = commentPopulateUser(c, usr)

	return &cmv1.CommentCensorReply{
		Comment: c,
	}, nil
}

func (c *Comments) processComments(ctx context.Context, c cmv1.Comments, usr *user.User) (*cmv1.CommentsReply, error) {
	log.Tracef("processComments: %v", c.Token)

	// Only admins and the proposal author are allowed to retrieve
	// unvetted comments. This is a public route so a user might not
	// exist.
	if c.State == cmv1.RecordStateUnvetted {
		var isAllowed bool
		switch {
		case usr == nil:
		// No logged in user. Unvetted not allowed.
		case usr.Admin:
			// User is an admin. Unvetted is allowed.
			isAllowed = true
		default:
			// Logged in user is not an admin. Check if they are the
			// proposal author.
			pr, err := p.proposalRecordLatest(ctx, c.State, c.Token)
			if err != nil {
				if errors.Is(err, errProposalNotFound) {
					return nil, cmv1.UserErrorReply{
						ErrorCode: cmv1.ErrorCodePropNotFound,
					}
				}
				return nil, fmt.Errorf("proposalRecordLatest: %v", err)
			}
			if usr.ID.String() == pr.UserID {
				// User is the proposal author. Unvetted is allowed.
				isAllowed = true
			}
		}
		if !isAllowed {
			return nil, cmv1.UserErrorReply{
				ErrorCode:    cmv1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Send plugin command
	reply, err := p.commentsAll(ctx, comments.GetAll{})
	if err != nil {
		return nil, err
	}

	// Prepare reply. Comments contain user data that needs to be
	// pulled from the user database.
	cs := make([]cmv1.Comment, 0, len(reply.Comments))
	for _, cm := range reply.Comments {
		// Convert comment
		pic := convertCommentFromPlugin(cm)

		// Get comment user data
		uuid, err := uuid.Parse(cm.UserID)
		if err != nil {
			return nil, err
		}
		u, err := p.db.UserGetById(uuid)
		if err != nil {
			return nil, err
		}
		pic.Username = u.Username

		// Add comment
		cs = append(cs, pic)
	}

	return &cmv1.CommentsReply{
		Comments: cs,
	}, nil
}

func (c *Comments) processCommentVotes(ctx context.Context, cv cmv1.CommentVotes) (*cmv1.CommentVotesReply, error) {
	log.Tracef("processCommentVotes: %v %v", cv.Token, cv.UserID)

	// Verify state
	if cv.State != cmv1.RecordStateVetted {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodeRecordStateInvalid,
			ErrorContext: "proposal must be vetted",
		}
	}

	// Send plugin command
	v := comments.Votes{
		UserID: cv.UserID,
	}
	cvr, err := p.commentVotes(ctx, v)
	if err != nil {
		return nil, err
	}

	return &cmv1.CommentVotesReply{
		Votes: convertCommentVoteDetailsFromPlugin(cvr.Votes),
	}, nil
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

func (c *Comments) handleCommentDel(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentDel")

	var d cmv1.Del
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&d); err != nil {
		respondWithPiError(w, r, "handleCommentDel: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentDel: getSessionUser: %v", err)
		return
	}

	dr, err := p.processCommentDel(r.Context(), d, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentDel: processCommentDel: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, dr)
}

func (c *Comments) handleCommentsCount(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentsCount")

	var c cmv1.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithPiError(w, r, "handleCommentsCount: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposalInventory: getSessionUser: %v", err)
		return
	}

	cr, err := p.processCommentsCount(r.Context(), c, usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processCommentsCount: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

func (c *Comments) handleComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleComments")

	var c cmv1.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithPiError(w, r, "handleComments: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithPiError(w, r,
			"handleProposalInventory: getSessionUser: %v", err)
		return
	}

	cr, err := p.processComments(r.Context(), c, usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processComments: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

func (c *Comments) handleCommentVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVotes")

	var v cmv1.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		respondWithPiError(w, r, "handleCommentVotes: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	vr, err := p.processCommentVotes(r.Context(), v)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVotes: processCommentVotes: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
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
	usr, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		respondWithCommentsError(w, r,
			"handleCommentTimestamps: getSessionUser: %v", err)
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
