// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/plugins/comments"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/util"
)

func convertCommentState(s cmv1.RecordStateT) comments.StateT {
	switch s {
	case cmv1.RecordStateUnvetted:
		return comments.StateUnvetted
	case cmv1.RecordStateVetted:
		return comments.StateVetted
	}
	return comments.StateInvalid
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

// commentsAll returns all comments for the provided record.
func (p *politeiawww) commentsAll(ctx context.Context, cp comments.GetAll) (*comments.GetAllReply, error) {
	b, err := comments.EncodeGetAll(cp)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, comments.ID, comments.CmdGetAll, string(b))
	if err != nil {
		return nil, err
	}
	cr, err := comments.DecodeGetAllReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cr, nil
}

// commentsGet returns the set of comments specified in the comment's id slice.
func (p *politeiawww) commentsGet(ctx context.Context, cg comments.Get) (*comments.GetReply, error) {
	b, err := comments.EncodeGet(cg)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, comments.ID, comments.CmdGet, string(b))
	if err != nil {
		return nil, err
	}
	cgr, err := comments.DecodeGetReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cgr, nil
}

// commentVotes returns the comment votes that meet the provided criteria.
func (p *politeiawww) commentVotes(ctx context.Context, vs comments.Votes) (*comments.VotesReply, error) {
	b, err := comments.EncodeVotes(vs)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, comments.ID, comments.CmdVotes, string(b))
	if err != nil {
		return nil, err
	}
	vsr, err := comments.DecodeVotesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return vsr, nil
}

func (p *politeiawww) commentTimestamps(ctx context.Context, t comments.Timestamps) (*comments.TimestampsReply, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, comments.ID,
		comments.CmdTimestamps, string(b))
	if err != nil {
		return nil, err
	}
	var tr comments.TimestampsReply
	err = json.Unmarshal([]byte(r), &tr)
	if err != nil {
		return nil, err
	}
	return &tr, nil
}

func (p *politeiawww) processCommentTimestamps(ctx context.Context, t cmv1.Timestamps, isAdmin bool) (*cmv1.TimestampsReply, error) {
	log.Tracef("processCommentTimestamps: %v %v %v",
		t.State, t.Token, t.CommentIDs)

	// Get timestamps
	ct := comments.Timestamps{
		State:      convertCommentState(t.State),
		Token:      t.Token,
		CommentIDs: t.CommentIDs,
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

func (p *politeiawww) handleCommentTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentTimestamps")

	var t cmv1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithCommentsError(w, r, "handleTimestamps: unmarshal",
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
			"handleTimestamps: getSessionUser: %v", err)
		return
	}

	isAdmin := usr != nil && usr.Admin
	tr, err := p.processCommentTimestamps(r.Context(), t, isAdmin)
	if err != nil {
		respondWithCommentsError(w, r,
			"handleTimestamps: processTimestamps: %v", err)
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
