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
	case "edituser":
		fmt.Printf("%s\n", EditUserCmdHelpMsg)
	case "subscribe":
		fmt.Printf("%s\n", SubscribeCmdHelpMsg)
	case "me":
		fmt.Printf("%s\n", MeCmdHelpMsg)
	case "policy":
		fmt.Printf("%s\n", PolicyCmdHelpMsg)
	case "resetpassword":
		fmt.Printf("%s\n", ResetPasswordCmdHelpMsg)
	case "updateuserkey":
		fmt.Printf("%s\n", UpdateUserKeyCmdHelpMsg)
	case "getpaywallpayment":
		fmt.Printf("%s\n", GetPaywallPaymentCmdHelpMsg)
	case "proposalpaywall":
		fmt.Printf("%s\n", ProposalPaywallCmdHelpMsg)
	case "rescanuserpayments":
		fmt.Printf("%s\n", RescanUserPaymentsCmdHelpMsg)
	case "verifyuserpayment":
		fmt.Printf("%s\n", VerifyUserPaymentCmdHelpMsg)
	case "startvote":
		fmt.Printf("%s\n", StartVoteCmdHelpMsg)
	case "proposalvotes":
		fmt.Printf("%s\n", ProposalVotesCmdHelpMsg)
	case "votestatus":
		fmt.Printf("%s\n", VoteStatusCmdHelpMsg)
	case "inventory":
		fmt.Printf("%s\n", InventoryCmdHelpMsg)
	case "tally":
		fmt.Printf("%s\n", TallyCmdHelpMsg)
	case "commentslikes":
		fmt.Printf("%s\n", CommentsLikesCmdHelpMsg)
	default:
		fmt.Printf("invalid command\n")
	}

	return nil
}
