// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

/*
func convertCommentVoteFromPi(cv piv1.CommentVoteT) comments.VoteT {
	switch cv {
	case piv1.CommentVoteDownvote:
		return comments.VoteUpvote
	case piv1.CommentVoteUpvote:
		return comments.VoteDownvote
	}
	return comments.VoteInvalid
}

func convertCommentFromPlugin(c comments.Comment) piv1.Comment {
	return piv1.Comment{
		UserID:    c.UserID,
		Username:  "", // Intentionally omitted, needs to be pulled from userdb
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		PublicKey: c.PublicKey,
		Signature: c.Signature,
		CommentID: c.CommentID,
		Timestamp: c.Timestamp,
		Receipt:   c.Receipt,
		Downvotes: c.Downvotes,
		Upvotes:   c.Upvotes,
		Censored:  c.Deleted,
		Reason:    c.Reason,
	}
}

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

func (p *politeiawww) commentsAll(ctx context.Context, ga comments.GetAll) (*comments.GetAllReply, error) {
	return nil, nil
}

func (p *politeiawww) commentsGet(ctx context.Context, cg comments.Get) (*comments.GetReply, error) {
	return nil, nil
}

func (p *politeiawww) commentVotes(ctx context.Context, vs comments.Votes) (*comments.VotesReply, error) {
	return nil, nil
}

func (p *politeiawww) commentTimestamps(ctx context.Context, t comments.Timestamps) (*comments.TimestampsReply, error) {
	return nil, nil
}

// commentPopulateUser populates the provided comment with user data that is
// not stored in politeiad.
func commentPopulateUser(c piv1.Comment, u user.User) cmv1.Comment {
	c.Username = u.Username
	return c
}

func (p *politeiawww) commentNewPi(ctx context.Context, n cmv1.CommentNew, u user.User) error {
	// Verify user has paid registration paywall
	if !p.userHasPaid(u) {
		return nil, cmv1.UserErrorReply{
			ErrorCode: cmv1.ErrorCodeUserRegistrationNotPaid,
		}
	}
	return nil
}

func (p *politeiawww) processCommentNew(ctx context.Context, n cmv1.CommentNew, u user.User) (*cmv1.CommentNewReply, error) {
	log.Tracef("processCommentNew: %v %v", n.Token, u.Username)

	// This is temporary until user plugins are implemented.
	switch p.mode {
	case politeiaWWWMode:
		err := p.commentNewPi(ctx, n, u)
		if err != nil {
			return nil, err
		}
	}

	// Verify user signed using active identity
	if u.PublicKey() != n.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Only admins and the record author are allowed to comment on
	// unvetted records.
	if n.State == cmv1.PropStateUnvetted && !u.Admin {
		// Get the record author
		// TODO create a user politeiad plugin
		// TODO add command to get author for record
		// Fetch the proposal so we can see who the author is
		pr, err := p.proposalRecordLatest(ctx, n.State, n.Token)
		if err != nil {
			if errors.Is(err, errProposalNotFound) {
				return nil, cmv1.UserErrorReply{
					ErrorCode: cmv1.ErrorCodeRecordNotFound,
				}
			}
			return nil, fmt.Errorf("proposalRecordLatest: %v", err)
		}
		if u.ID.String() != pr.UserID {
			return nil, cmv1.UserErrorReply{
				ErrorCode:    cmv1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Send plugin command
	n := comments.New{
		UserID:    usr.ID.String(),
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
	}
	// TODO
	_ = n
	var nr comments.NewReply

	// Prepare reply
	c := convertCommentFromPlugin(nr.Comment)
	c = commentPopulateUser(c, u)

	// Emit event
	p.eventManager.emit(eventProposalComment,
		dataProposalComment{
			state:     c.State,
			token:     c.Token,
			commentID: c.CommentID,
			parentID:  c.ParentID,
			username:  c.Username,
		})

	return &cmv1.CommentNewReply{
		Comment: c,
	}, nil
}

func (p *politeiawww) processCommentVote(ctx context.Context, cv cmv1.CommentVote, usr user.User) (*cmv1.CommentVoteReply, error) {
	log.Tracef("processCommentVote: %v %v %v", cv.Token, cv.CommentID, cv.Vote)

	// Verify state
	if cv.State != cmv1.PropStateVetted {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePropStateInvalid,
			ErrorContext: "proposal must be vetted",
		}
	}

	// Verify user has paid registration paywall
	if !p.userHasPaid(usr) {
		return nil, cmv1.UserErrorReply{
			ErrorCode: cmv1.ErrorCodeUserRegistrationNotPaid,
		}
	}

	// Verify user signed using active identity
	if usr.PublicKey() != cv.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	v := comments.Vote{
		UserID:    usr.ID.String(),
		Token:     cv.Token,
		CommentID: cv.CommentID,
		Vote:      convertCommentVoteFromPi(cv.Vote),
		PublicKey: cv.PublicKey,
		Signature: cv.Signature,
	}
	// TODO
	_ = v
	var vr comments.VoteReply

	return &cmv1.CommentVoteReply{
		Downvotes: vr.Downvotes,
		Upvotes:   vr.Upvotes,
		Timestamp: vr.Timestamp,
		Receipt:   vr.Receipt,
	}, nil
}

func (p *politeiawww) processCommentCensor(ctx context.Context, cc cmv1.CommentCensor, usr user.User) (*cmv1.CommentCensorReply, error) {
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

func (p *politeiawww) processComments(ctx context.Context, c cmv1.Comments, usr *user.User) (*cmv1.CommentsReply, error) {
	log.Tracef("processComments: %v", c.Token)

	// Only admins and the proposal author are allowed to retrieve
	// unvetted comments. This is a public route so a user might not
	// exist.
	if c.State == cmv1.PropStateUnvetted {
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

func (p *politeiawww) processCommentVotes(ctx context.Context, cv cmv1.CommentVotes) (*cmv1.CommentVotesReply, error) {
	log.Tracef("processCommentVotes: %v %v", cv.Token, cv.UserID)

	// Verify state
	if cv.State != cmv1.PropStateVetted {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePropStateInvalid,
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

func (p *politeiawww) processCommentTimestamps(ctx context.Context, t cmv1.Timestamps, isAdmin bool) (*cmv1.TimestampsReply, error) {
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

func (p *politeiawww) handleCommentNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentNew")

	var n cmv1.New
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		respondWithPiError(w, r, "handleCommentNew: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: getSessionUser: %v", err)
		return
	}

	nr, err := p.processCommentNew(r.Context(), n, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentNew: processCommentNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, nr)
}

func (p *politeiawww) handleCommentVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentVote")

	var v cmv1.Vote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithPiError(w, r, "handleCommentVote: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	usr, err := p.getSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: getSessionUser: %v", err)
		return
	}

	vr, err := p.processCommentVote(r.Context(), v, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"handleCommentVote: processCommentVote: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleCommentDel(w http.ResponseWriter, r *http.Request) {
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

func (p *politeiawww) handleCommentsCount(w http.ResponseWriter, r *http.Request) {
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

func (p *politeiawww) handleComments(w http.ResponseWriter, r *http.Request) {
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

func (p *politeiawww) handleCommentVotes(w http.ResponseWriter, r *http.Request) {
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

func (p *politeiawww) handleCommentTimestamps(w http.ResponseWriter, r *http.Request) {
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

func respondWithCommentsError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue cmv1.UserErrorReply
		pe pdError
	)
	switch {
	case errors.As(err, &ue):
		// Comments user error
		m := fmt.Sprintf("Comments user error: %v %v %v",
			remoteAddr(r), ue.ErrorCode, cmv1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			cmv1.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return

	case errors.As(err, &pe):
		// Politeiad error
		var (
			pluginID   = pe.ErrorReply.Plugin
			errCode    = pe.ErrorReply.ErrorCode
			errContext = pe.ErrorReply.ErrorContext
		)
		switch {
		case pluginID != "":
			// Politeiad plugin error. Log it and return a 400.
			m := fmt.Sprintf("Plugin error: %v %v %v",
				remoteAddr(r), pluginID, errCode)
			if len(errContext) > 0 {
				m += fmt.Sprintf(": %v", strings.Join(errContext, ", "))
			}
			log.Infof(m)
			util.RespondWithJSON(w, http.StatusBadRequest,
				cmv1.PluginErrorReply{
					PluginID:     pluginID,
					ErrorCode:    errCode,
					ErrorContext: strings.Join(errContext, ", "),
				})
			return

		default:
			// Unknown politeiad error. Log it and return a 500.
			ts := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error code "+
				"from politeiad: %v", remoteAddr(r), r.Method, r.URL,
				r.Proto, ts, errCode)

			util.RespondWithJSON(w, http.StatusInternalServerError,
				cmv1.ServerErrorReply{
					ErrorCode: ts,
				})
			return
		}

	default:
		// Internal server error. Log it and return a 500.
		t := time.Now().Unix()
		e := fmt.Sprintf(format, err)
		log.Errorf("%v %v %v %v Internal error %v: %v",
			remoteAddr(r), r.Method, r.URL, r.Proto, t, e)
		log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

		util.RespondWithJSON(w, http.StatusInternalServerError,
			cmv1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}
*/
