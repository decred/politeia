package commands

// Help message displayed for the command 'politeiawwwcli help commentslikes'
var CommentsLikesCmdHelpMsg = `commentslikes "token"

Fetch all the comments voted on by the user for a given proposal. 

Arguments:
1. token       (string, required)  Proposal censorship token

Result:

{
  "commentslikes": [
    {
      "action":    (string)  Vote (upvote or downvote)
      "commentid"  (string)  Id of the comment
      "token":     (string)  Proposal censorship token
    },
  ]
}`

type CommentsLikesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *CommentsLikesCmd) Execute(args []string) error {
	cvr, err := c.UserCommentsLikes(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(cvr, cfg.Verbose, cfg.RawJSON)
}
