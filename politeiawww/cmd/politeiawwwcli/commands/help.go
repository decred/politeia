package commands

import "fmt"

type HelpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic" description:"get information about available commands"`
	} `positional-args:"true"  required:"true"`
}

func (cmd *HelpCmd) Execute(args []string) error {

	switch cmd.Args.Topic {
	case "login":
		fmt.Printf("%s\n", LoginCmdHelpMsg)
	case "logout":
		fmt.Printf("%s\n", LogoutCmdHelpMsg)
	case "authorizevote":
		fmt.Printf("%s\n", AuthorizeVoteCmdHelpMsg)
	case "newuser":
		fmt.Printf("%s\n", NewUserCmdHelpMsg)
	case "newproposal":
		fmt.Printf("%s\n", NewProposalCmdHelpMsg)
	case "changepassword":
		fmt.Printf("%s\n", ChangePasswordCmdHelpMsg)
	case "changeusername":
		fmt.Printf("%s\n", ChangeUsernameCmdHelpMsg)
	case "faucet":
		fmt.Printf("%s\n", FaucetCmdHelpMsg)
	case "userdetails":
		fmt.Printf("%s\n", UserDetailsCmdHelpMsg)
	case "getproposal":
		fmt.Printf("%s\n", GetProposalCmdHelpMsg)
	case "userproposals":
		fmt.Printf("%s\n", UserProposalsCmdHelpMsg)
	case "getunvetted":
		fmt.Printf("%s\n", GetUnvettedCmdHelpMsg)
	case "getvetted":
		fmt.Printf("%s\n", GetVettedCmdHelpMsg)
	case "setproposalstatus":
		fmt.Printf("%s\n", SetProposalStatusCmdHelpMsg)
	case "newcomment":
		fmt.Printf("%s\n", NewCommentCmdHelpMsg)
	case "getcomments":
		fmt.Printf("%s\n", GetCommentsCmdHelpMsg)
	case "censorcomment":
		fmt.Printf("%s\n", CensorCommentCmdHelpMsg)
	case "votecomment":
		fmt.Printf("%s\n", VoteCommentCmdHelpMsg)
	case "editproposal":
		fmt.Printf("%s\n", EditProposalCmdHelpMsg)
	case "manageuser":
		fmt.Printf("%s\n", ManageUserCmdHelpMsg)
	case "users":
		fmt.Printf("%s\n", UsersCmdHelpMsg)
	case "verifyuser":
		fmt.Printf("%s\n", VerifyUserCmdHelpMsg)
	case "version":
		fmt.Printf("%s\n", VersionCmdHelpMsg)
	case "vote":
		fmt.Printf("%s\n", VoteCmdHelpMsg)
	case "edituser":
		fmt.Printf("%s\n", EditUserCmdHelpMsg)
	default:
		fmt.Printf("invalid command\n")
	}

	return nil
}
