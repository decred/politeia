package main

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
)

func (b *backend) decredGetComment(token, commentID string) (*decredplugin.Comment, error) {
	// Setup plugin command
	gc := decredplugin.GetComment{
		Token:     token,
		CommentID: commentID,
	}

	gcb, err := decredplugin.EncodeGetComment(gc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdGetComment,
		CommandPayload: string(gcb),
	}

	// Fetch comment from the cache
	reply, err := b.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	gcr, err := decredplugin.DecodeGetCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return &gcr.Comment, nil
}

func (b *backend) decredGetComments(token string) ([]decredplugin.Comment, error) {
	// Setup plugin command
	gc := decredplugin.GetComments{
		Token: token,
	}

	gcb, err := decredplugin.EncodeGetComments(gc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdGetComments,
		CommandPayload: string(gcb),
	}

	// Fetch comments from the cache
	reply, err := b.cache.PluginExec(pc)
	if err != nil {
		return nil, fmt.Errorf("PluginExec: %v", err)
	}

	gcr, err := decredplugin.DecodeGetCommentsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return gcr.Comments, nil
}

func (b *backend) decredLikeComments(token, commentID string) ([]decredplugin.LikeComment, error) {
	// Setup plugin command
	cl := decredplugin.CommentLikes{
		Token:     token,
		CommentID: commentID,
	}

	payload, err := decredplugin.EncodeCommentLikes(cl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdCommentLikes,
		CommandPayload: string(payload),
	}

	// Fetch comment likes from cache
	reply, err := b.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	clr, err := decredplugin.DecodeCommentLikesReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return clr.CommentLikes, nil
}

func (b *backend) decredPropLikeComments(token string) ([]decredplugin.LikeComment, error) {
	// Setup plugin command
	pcl := decredplugin.GetProposalCommentsLikes{
		Token: token,
	}

	payload, err := decredplugin.EncodeGetProposalCommentsLikes(pcl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdProposalCommentsLikes,
		CommandPayload: string(payload),
	}

	// Fetch proposal comment likes from cache
	reply, err := b.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	p := []byte(reply.Payload)
	pclr, err := decredplugin.DecodeGetProposalCommentsLikesReply(p)
	if err != nil {
		return nil, err
	}

	return pclr.CommentsLikes, nil
}

func (b *backend) decredInventory() (*decredplugin.InventoryReply, error) {
	// Setup plugin command
	i := decredplugin.Inventory{}
	ib, err := decredplugin.EncodeInventory(i)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdInventory,
		CommandPayload: string(ib),
	}

	// Fetch cache inventory
	reply, err := b.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	ir, err := decredplugin.DecodeInventoryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return ir, nil
}
