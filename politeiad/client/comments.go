// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

/*
// CommentNew sends the comments plugin New command to the politeiad v1 API.
func (c *Client) CommentNew(ctx context.Context, state string, n comments.New) (*comments.NewReply, error) {
	// Setup request
	b, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	cmd := pdv2.PluginCmd{
		Token:   n.Token,
		ID:      comments.PluginID,
		Command: comments.CmdNew,
		Payload: string(b),
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var nr comments.NewReply
	err = json.Unmarshal([]byte(pcr.Payload), &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

// CommentVote sends the comments plugin Vote command to the politeiad v1 API.
func (c *Client) CommentVote(ctx context.Context, state string, v comments.Vote) (*comments.VoteReply, error) {
	// Setup request
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionWrite,
			State:   state,
			Token:   v.Token,
			ID:      comments.PluginID,
			Command: comments.CmdVote,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var vr comments.VoteReply
	err = json.Unmarshal([]byte(pcr.Payload), &vr)
	if err != nil {
		return nil, err
	}

	return &vr, nil
}

// CommentDel sends the comments plugin Del command to the politeiad v1 API.
func (c *Client) CommentDel(ctx context.Context, state string, d comments.Del) (*comments.DelReply, error) {
	// Setup request
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionWrite,
			State:   state,
			Token:   d.Token,
			ID:      comments.PluginID,
			Command: comments.CmdDel,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var dr comments.DelReply
	err = json.Unmarshal([]byte(pcr.Payload), &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// CommentCount sends a batch of comment plugin Count commands to the
// politeiad v1 API and returns a map[token]count with the results. If a record
// is not found for a token or any other error occurs, that token will not be
// included in the reply.
func (c *Client) CommentCount(ctx context.Context, state string, tokens []string) (map[string]uint32, error) {
	// Setup request
	cmds := make([]pdv1.PluginCommandV2, 0, len(tokens))
	for _, v := range tokens {
		cmds = append(cmds, pdv1.PluginCommandV2{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   v,
			ID:      comments.PluginID,
			Command: comments.CmdCount,
		})
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) != len(cmds) {
		return nil, fmt.Errorf("replies missing")
	}

	// Decode replies
	counts := make(map[string]uint32, len(replies))
	for _, v := range replies {
		// This command swallows individual errors. The token of the
		// command that errored will not be included in the reply.
		err = extractPluginCommandError(v)
		if err != nil {
			spew.Dump(err)
			continue
		}

		var cr comments.CountReply
		err = json.Unmarshal([]byte(v.Payload), &cr)
		if err != nil {
			continue
		}
		counts[v.Token] = cr.Count
	}

	return counts, nil
}

// CommentsGet sends the comments plugin Get command to the politeiad v1 API.
func (c *Client) CommentsGet(ctx context.Context, state, token string, g comments.Get) (map[uint32]comments.Comment, error) {
	// Setup request
	b, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdGet,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var gr comments.GetReply
	err = json.Unmarshal([]byte(pcr.Payload), &gr)
	if err != nil {
		return nil, err
	}

	return gr.Comments, nil
}

// CommentsGetAll sends the comments plugin GetAll command to the politeiad v1
// API.
func (c *Client) CommentsGetAll(ctx context.Context, state, token string) ([]comments.Comment, error) {
	// Setup request
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdGetAll,
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var gar comments.GetAllReply
	err = json.Unmarshal([]byte(pcr.Payload), &gar)
	if err != nil {
		return nil, err
	}

	return gar.Comments, nil
}

// CommentVotes sends the comments plugin Votes command to the politeiad v1
// API.
func (c *Client) CommentVotes(ctx context.Context, state, token string, v comments.Votes) ([]comments.CommentVote, error) {
	// Setup request
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdVotes,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var vr comments.VotesReply
	err = json.Unmarshal([]byte(pcr.Payload), &vr)
	if err != nil {
		return nil, err
	}

	return vr.Votes, nil
}

// CommentTimestamps sends the comments plugin Timestamps command to the
// politeiad v1 API.
func (c *Client) CommentTimestamps(ctx context.Context, state, token string, t comments.Timestamps) (*comments.TimestampsReply, error) {
	// Setup request
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	cmds := []pdv1.PluginCommandV2{
		{
			Action:  pdv1.PluginActionRead,
			State:   state,
			Token:   token,
			ID:      comments.PluginID,
			Command: comments.CmdTimestamps,
			Payload: string(b),
		},
	}

	// Send request
	replies, err := c.PluginCommandBatch(ctx, cmds)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, fmt.Errorf("no replies found")
	}
	pcr := replies[0]
	err = extractPluginCommandError(pcr)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var tr comments.TimestampsReply
	err = json.Unmarshal([]byte(pcr.Payload), &tr)
	if err != nil {
		return nil, err
	}

	return &tr, nil
}
*/
