package commands

// Help message displayed for the command 'politeiawwwcli help getcomments'
var GetCommentsCmdHelpMsg = `getcomments "token" 

Get comments for a proposal.

Arguments:
1. token       (string, required)   Proposal censorship token

Result:
{
  "comments": [
    {
      "token":        (string)  Censorship token
      "parentid":     (string)  Id of comment (defaults to '0' (top-level))
      "comment":      (string)  Comment
      "signature":    (string)  Signature of token+parentID+comment
      "publickey":    (string)  Public key of user 
      "commentid":    (string)  Id of the comment
      "receipt":      (string)  Server signature of the comment signature
      "timestamp":    (int64)   Received UNIX timestamp
      "totalvotes":   (uint64)  Total number of up/down votes
      "resultvotes":  (int64)   Vote score
      "censored":     (bool)    If comment has been censored
      "userid":       (string)  User id
      "username":     (string)  Username
    }
  ]
}`

type GetCommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *GetCommentsCmd) Execute(args []string) error {
	gcr, err := c.GetComments(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(gcr, cfg.Verbose, cfg.RawJSON)
}
