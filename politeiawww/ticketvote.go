// Copyright (c) 2020 The Decred developers
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

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/util"
)

func convertProofFromTicketVotePlugin(p ticketvote.Proof) tkv1.Proof {
	return tkv1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampFromTicketVotePlugin(t ticketvote.Timestamp) tkv1.Timestamp {
	proofs := make([]tkv1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofFromTicketVotePlugin(v))
	}
	return tkv1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}

func (p *politeiawww) voteAuthorize(ctx context.Context, a ticketvote.Authorize) (*ticketvote.AuthorizeReply, error) {
	return nil, nil
}

func (p *politeiawww) voteStart(ctx context.Context, s ticketvote.Start) (*ticketvote.StartReply, error) {
	return nil, nil
}

func (p *politeiawww) castBallot(ctx context.Context, tb ticketvote.CastBallot) (*ticketvote.CastBallotReply, error) {
	return nil, nil
}

func (p *politeiawww) voteDetails(ctx context.Context, token string) (*ticketvote.DetailsReply, error) {
	return nil, nil
}

func (p *politeiawww) voteResults(ctx context.Context, token string) (*ticketvote.ResultsReply, error) {
	return nil, nil
}

func (p *politeiawww) voteSummaries(ctx context.Context, tokens []string) (map[string]ticketvote.VoteSummary, error) {

	return nil, nil
}

func (p *politeiawww) voteTimestamps(ctx context.Context, token string) (*ticketvote.TimestampsReply, error) {
	_ = token
	var b []byte
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdTimestamps, string(b))
	if err != nil {
		return nil, err
	}
	var tr ticketvote.TimestampsReply
	err = json.Unmarshal([]byte(r), &tr)
	if err != nil {
		return nil, err
	}
	return &tr, nil
}

func (p *politeiawww) processTicketVoteTimestamps(ctx context.Context, t tkv1.Timestamps) (*tkv1.TimestampsReply, error) {
	log.Tracef("processTicketVoteTimestamps: %v", t.Token)

	// Send plugin command
	r, err := p.voteTimestamps(ctx, t.Token)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	var (
		auths = make([]tkv1.Timestamp, 0, len(r.Auths))
		votes = make(map[string]tkv1.Timestamp, len(r.Votes))

		details = convertTimestampFromTicketVotePlugin(r.Details)
	)
	for _, v := range r.Auths {
		auths = append(auths, convertTimestampFromTicketVotePlugin(v))
	}
	for k, v := range r.Votes {
		votes[k] = convertTimestampFromTicketVotePlugin(v)
	}

	return &tkv1.TimestampsReply{
		Auths:   auths,
		Details: details,
		Votes:   votes,
	}, nil
}

func (p *politeiawww) handleTicketVoteTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleTicketVoteTimestamps")

	var t tkv1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithTicketVoteError(w, r, "handleTicketVoteTimestamps: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	tr, err := p.processTicketVoteTimestamps(r.Context(), t)
	if err != nil {
		respondWithTicketVoteError(w, r,
			"handleTicketVoteTimestamps: processTicketVoteTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tr)
}

func respondWithTicketVoteError(w http.ResponseWriter, r *http.Request, format string, err error) {
	var (
		ue tkv1.UserErrorReply
		pe pdError
	)
	switch {
	case errors.As(err, &ue):
		// Ticket vote user error
		m := fmt.Sprintf("Ticket vote user error: %v %v %v",
			remoteAddr(r), ue.ErrorCode, tkv1.ErrorCodes[ue.ErrorCode])
		if ue.ErrorContext != "" {
			m += fmt.Sprintf(": %v", ue.ErrorContext)
		}
		log.Infof(m)
		util.RespondWithJSON(w, http.StatusBadRequest,
			tkv1.UserErrorReply{
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
				tkv1.PluginErrorReply{
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
				tkv1.ServerErrorReply{
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
			tkv1.ServerErrorReply{
				ErrorCode: t,
			})
		return
	}
}
