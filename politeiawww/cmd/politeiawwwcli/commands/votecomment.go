package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type VotecommentCmd struct {
	Args struct {
		Token     string `positional-arg-name:"token"`
		CommentID string `positional-arg-name:"commentID"`
		Action    string `positional-arg-name:"action"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VotecommentCmd) Execute(args []string) error {
	if cmd.Args.Action != "downvote" && cmd.Args.Action != "upvote" {
		return fmt.Errorf("invalid action %s. The action must be either downvote or upvote", cmd.Args.Action)
	}
	_, err := Ctx.CommentVote(config.UserIdentity, cmd.Args.Token, cmd.Args.CommentID,
		cmd.Args.Action)
	return err
}
