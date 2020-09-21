// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/plugins/comments"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// commentCensor calls the comments plugin to censor a given comment.
func (p *politeiawww) commentCensor(cc comments.Del) (*comments.DelReply, error) {
	// Prep plugin payload
	payload, err := comments.EncodeDel(cc)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(comments.ID, comments.CmdDel, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	ccr, err := comments.DecodeDelReply(([]byte(r)))
	if err != nil {
		return nil, err
	}

	return ccr, nil
}

// comments calls the comments plugin to get record's comments.
func (p *politeiawww) comments(cp comments.GetAll) (*comments.GetAllReply, error) {
	// Prep plugin payload
	payload, err := comments.EncodeGetAll(cp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(comments.ID, comments.CmdGetAll, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cr, err := comments.DecodeGetAllReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func validateComment(c www.NewComment) error {
	// max length
	if len(c.Comment) > www.PolicyMaxCommentLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		}
	}
	// validate token
	if !tokenIsValid(c.Token) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}
	return nil
}

// processNewComment sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewComment(nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewComment: %v %v", nc.Token, u.ID)

	/*
		// Make sure token is valid and not a prefix
		if !isTokenValid(nc.Token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{nc.Token},
			}
		}

		// Pay up sucker!
		if !p.HasUserPaid(u) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotPaid,
			}
		}

		// Ensure the public key is the user's active key
		if nc.PublicKey != u.PublicKey() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			}
		}

		// Validate signature
		msg := nc.Token + nc.ParentID + nc.Comment
		err := validateSignature(nc.PublicKey, nc.Signature, msg)
		if err != nil {
			return nil, err
		}

		// Validate comment
		err = validateComment(nc)
		if err != nil {
			return nil, err
		}

		// Ensure proposal exists and is public
		pr, err := p.getProp(nc.Token)
		if err != nil {
				if err == cache.ErrRecordNotFound {
					err = www.UserError{
						ErrorCode: www.ErrorStatusProposalNotFound,
					}
				}
			return nil, err
		}

		if pr.Status != www.PropStatusPublic {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongStatus,
				ErrorContext: []string{"proposal is not public"},
			}
		}

		// Ensure proposal voting has not ended
		bb, err := p.getBestBlock()
		if err != nil {
			return nil, fmt.Errorf("getBestBlock: %v", err)
		}
		vs, err := p.voteSummaryGet(nc.Token, bb)
		if err != nil {
			return nil, fmt.Errorf("voteSummaryGet: %v", err)
		}
		if vs.Status == www.PropVoteStatusFinished {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote is finished"},
			}
		}

		// Ensure the comment is not a duplicate
		_, err = p.decredCommentGetBySignature(nc.Token, nc.Signature)
		switch err {
		case nil:
			// Duplicate comment was found
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusDuplicateComment,
			}
		// No duplicate comment; continue
		default:
			// Some other error
			return nil, fmt.Errorf("decredCommentBySignature: %v", err)
		}

		// Setup plugin command
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		dnc := convertNewCommentToDecredPlugin(nc)
		payload, err := decredplugin.EncodeNewComment(dnc)
		if err != nil {
			return nil, err
		}

		pc := pd.PluginCommand{
			Challenge: hex.EncodeToString(challenge),
			ID:        decredplugin.ID,
			Command:   decredplugin.CmdNewComment,
			CommandID: decredplugin.CmdNewComment,
			Payload:   string(payload),
		}

		// Send polieiad request
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.PluginCommandRoute, pc)
		if err != nil {
			return nil, err
		}

		// Handle response
		var reply pd.PluginCommandReply
		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"PluginCommandReply: %v", err)
		}

		err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, err
		}

		ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
		if err != nil {
			return nil, err
		}

		// Add comment to commentVotes in-memory cache
		p.Lock()
		p.commentVotes[nc.Token+ncr.CommentID] = counters{}
		p.Unlock()

		// Get comment from cache
		c, err := p.getComment(nc.Token, ncr.CommentID)
		if err != nil {
			return nil, fmt.Errorf("getComment: %v", err)
		}

		// Emit event notification for a proposal comment
		p.eventManager.emit(eventProposalComment,
			dataProposalComment{
				token: pr.CensorshipRecord.Token,
				name: pr.Name,
				username: pr.Username,
				parentID: c.ParentID,
				commentID: c.CommentID,
				commentUsername: c.Username,
			})

		return &www.NewCommentReply{
			Comment: *c,
		}, nil
	*/

	return nil, nil
}

// processLikeComment processes an upvote/downvote on a comment.
func (p *politeiawww) processLikeComment(lc www.LikeComment, u *user.User) (*www.LikeCommentReply, error) {
	log.Debugf("processLikeComment: %v %v %v", lc.Token, lc.CommentID, u.ID)

	/*
		// Make sure token is valid and not a prefix
		if !isTokenValid(lc.Token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{lc.Token},
			}
		}

		// Pay up sucker!
		if !p.HasUserPaid(u) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotPaid,
			}
		}

		// Ensure the public key is the user's active key
		if lc.PublicKey != u.PublicKey() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			}
		}

		// Validate signature
		msg := lc.Token + lc.CommentID + lc.Action
		err := validateSignature(lc.PublicKey, lc.Signature, msg)
		if err != nil {
			return nil, err
		}

		// Ensure proposal exists and is public
		pr, err := p.getProp(lc.Token)
		if err != nil {
				if err == cache.ErrRecordNotFound {
					err = www.UserError{
						ErrorCode: www.ErrorStatusProposalNotFound,
					}
				}
			return nil, err
		}

		if pr.Status != www.PropStatusPublic {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusWrongStatus,
			}
		}

		// Ensure proposal voting has not ended
		bb, err := p.getBestBlock()
		if err != nil {
			return nil, fmt.Errorf("getBestBlock: %v", err)
		}
		vs, err := p.voteSummaryGet(pr.CensorshipRecord.Token, bb)
		if err != nil {
			return nil, err
		}
		if vs.Status == www.PropVoteStatusFinished {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote has ended"},
			}
		}

		// Ensure comment exists and has not been censored.
		c, err := p.decredCommentGetByID(lc.Token, lc.CommentID)
		if err != nil {
				if err == cache.ErrRecordNotFound {
					err = www.UserError{
						ErrorCode: www.ErrorStatusCommentNotFound,
					}
				}
			return nil, err
		}
		if c.Censored {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusCommentIsCensored,
			}
		}

		// Validate action
		action := lc.Action
		if len(lc.Action) > 10 {
			// Clip action to not fill up logs and prevent DOS of sorts
			action = lc.Action[0:9] + "..."
		}
		if action != www.VoteActionUp && action != www.VoteActionDown {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidLikeCommentAction,
			}
		}

		// Setup plugin command
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		dlc := convertLikeCommentToDecred(lc)
		payload, err := decredplugin.EncodeLikeComment(dlc)
		if err != nil {
			return nil, err
		}

		pc := pd.PluginCommand{
			Challenge: hex.EncodeToString(challenge),
			ID:        decredplugin.ID,
			Command:   decredplugin.CmdLikeComment,
			CommandID: decredplugin.CmdLikeComment,
			Payload:   string(payload),
		}

		// Send plugin command to politeiad
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.PluginCommandRoute, pc)
		if err != nil {
			return nil, err
		}

		// Handle response
		var reply pd.PluginCommandReply
		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal "+
				"PluginCommandReply: %v", err)
		}

		err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, err
		}

		lcr, err := decredplugin.DecodeLikeCommentReply([]byte(reply.Payload))
		if err != nil {
			return nil, err
		}

		// Update comment score in the in-memory cache
		votes, err := p.updateCommentVotes(lc.Token, lc.CommentID)
		if err != nil {
			log.Criticalf("processLikeComment: update comment score "+
				"failed token:%v commentID:%v error:%v", lc.Token,
				lc.CommentID, err)
		}

		return &www.LikeCommentReply{
			Result:    int64(votes.up - votes.down),
			Upvotes:   votes.up,
			Downvotes: votes.down,
			Receipt:   lcr.Receipt,
			Error:     lcr.Error,
		}, nil
	*/

	return nil, nil
}

func (p *politeiawww) processCensorComment(cc www.CensorComment, u *user.User) (*www.CensorCommentReply, error) {
	log.Tracef("processCensorComment: %v: %v", cc.Token, cc.CommentID)

	/*
		// Make sure token is valid and not a prefix
		if !isTokenValid(cc.Token) {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusInvalidCensorshipToken,
				ErrorContext: []string{cc.Token},
			}
		}

		// Ensure the public key is the user's active key
		if cc.PublicKey != u.PublicKey() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidSigningKey,
			}
		}

		// Validate signature
		msg := cc.Token + cc.CommentID + cc.Reason
		err := validateSignature(cc.PublicKey, cc.Signature, msg)
		if err != nil {
			return nil, err
		}

		// Ensure censor reason is present
		if cc.Reason == "" {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusCensorReasonCannotBeBlank,
			}
		}

		// Ensure comment exists and has not already been censored
		c, err := p.decredCommentGetByID(cc.Token, cc.CommentID)
		if err != nil {
			return nil, fmt.Errorf("decredGetComment: %v", err)
		}
		if c.Censored {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusCommentNotFound,
			}
		}

		// Ensure proposal voting has not ended
		bb, err := p.getBestBlock()
		if err != nil {
			return nil, fmt.Errorf("getBestBlock: %v", err)
		}
		vs, err := p.voteSummaryGet(cc.Token, bb)
		if err != nil {
			return nil, err
		}
		if vs.Status == www.PropVoteStatusFinished {
			return nil, www.UserError{
				ErrorCode:    www.ErrorStatusWrongVoteStatus,
				ErrorContext: []string{"vote has ended"},
			}
		}

		// Setup plugin command
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		dcc := convertCensorCommentToDecred(cc)
		payload, err := decredplugin.EncodeCensorComment(dcc)
		if err != nil {
			return nil, err
		}

		pc := pd.PluginCommand{
			Challenge: hex.EncodeToString(challenge),
			ID:        decredplugin.ID,
			Command:   decredplugin.CmdCensorComment,
			CommandID: decredplugin.CmdCensorComment,
			Payload:   string(payload),
		}

		// Send plugin request
		responseBody, err := p.makeRequest(http.MethodPost,
			pd.PluginCommandRoute, pc)
		if err != nil {
			return nil, err
		}

		// Handle response
		var reply pd.PluginCommandReply
		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, err
		}

		err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, err
		}

		ccr, err := decredplugin.DecodeCensorCommentReply([]byte(reply.Payload))
		if err != nil {
			return nil, err
		}

		return &www.CensorCommentReply{
			Receipt: ccr.Receipt,
		}, nil
	*/

	return nil, nil
}
