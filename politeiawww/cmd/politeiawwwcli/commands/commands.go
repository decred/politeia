package commands

import (
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

const (
	ErrorNoUserIdentity = "No user identity found.  You must login with a user."
	ErrorNoProposalFile = "You must either provide a markdown file or use the --random flag"
	ErrorBeforeAndAfter = "before and after flags cannot be used at the same time"
)

var cfg *config.Config
var c *client.Client

func SetConfig(config *config.Config) {
	cfg = config
}

func SetClient(client *client.Client) {
	c = client
}

type Cmds struct {
	AuthorizeVote     AuthorizeVoteCmd     `command:"authorizevote" description:"authorize a proposal vote (must be proposal author)"`
	CensorComment     CensorCommentCmd     `command:"censorcomment" description:"(admin) censor a proposal comment"`
	ChangePassword    ChangePasswordCmd    `command:"changepassword" description:"change the password for the currently logged in user"`
	CommentsVotes     CommentsVotesCmd     `command:"commentsvotes" description:"fetch all the comments voted by the user on a proposal"`
	ChangeUsername    ChangeUsernameCmd    `command:"changeusername" description:"change the username for the currently logged in user"`
	EditProposal      EditProposalCmd      `command:"editproposal" description:"edit a proposal"`
	EditUser          EditUserCmd          `command:"edituser" description:"(admin) edit the details for the given user id"`
	Faucet            FaucetCmd            `command:"faucet" description:"use the Decred testnet faucet to send DCR to an address"`
	GetComments       GetCommentsCmd       `command:"getcomments" description:"fetch a proposal's comments"`
	GetProposal       GetProposalCmd       `command:"getproposal" description:"fetch a proposal"`
	GetUnvetted       GetUnvettedCmd       `command:"getunvetted" description:"fetch unvetted proposals"`
	GetVetted         GetVettedCmd         `command:"getvetted" description:"fetch vetted proposals"`
	GetPaywallPayment GetPaywallPaymentCmd `command:"getpaywallpayment" description:"fetch payment details for a proposal paywall payment"`
	Inventory         InventoryCmd         `command:"inventory" description:"fetch the proposals that are being voted on"`
	Login             LoginCmd             `command:"login" description:"login to Politeia"`
	Logout            LogoutCmd            `command:"logout" description:"logout of Politeia"`
	Me                MeCmd                `command:"me" description:"return the user information of the currently logged in user"`
	NewProposal       NewProposalCmd       `command:"newproposal" description:"submit a new proposal to Politeia"`
	NewComment        NewCommentCmd        `command:"newcomment" description:"comment on a proposal"`
	NewUser           NewUserCmd           `command:"newuser" description:"create a new Politeia user"`
	Policy            PolicyCmd            `command:"policy" description:"fetch server policy"`
	ProposalPaywall   ProposalPaywallCmd   `command:"proposalpaywall" description:"fetch proposal paywall details"`
	ProposalVotes     ProposalVotesCmd     `command:"proposalvotes" description:"fetch vote results for a specific proposal"`
	ResetPassword     ResetPasswordCmd     `command:"resetpassword" description:"change the password for a user that is not currently logged in"`
	Secret            SecretCmd            `command:"secret" description:"ping politeiawww"`
	SetProposalStatus SetProposalStatusCmd `command:"setproposalstatus" description:"(admin) set the status of a proposal"`
	StartVote         StartVoteCmd         `command:"startvote" description:"(admin) start the voting period on a proposal"`
	Tally             TallyCmd             `command:"tally" description:"fetch the vote tally for a proposal"`
	UpdateUserKey     UpdateUserKeyCmd     `command:"updateuserkey" description:"generate a new identity for the user"`
	UsernamesByID     UsernamesByIDCmd     `command:"usernamesbyid" description:"fetch usernames by their user ids"`
	UserDetails       UserDetailsCmd       `command:"userdetails" description:"fetch a user's details by his user id"`
	UserProposals     UserProposalsCmd     `command:"userproposals" description:"fetch all proposals submitted by a specific user"`
	Users             UsersCmd             `command:"users" description:"fetch a list of users, optionally filtering them by email and/or username"`
	VerifyUser        VerifyUserCmd        `command:"verifyuser" description:"verify user's email address"`
	VerifyUserPayment VerifyUserPaymentCmd `command:"verifyuserpayment" description:"check if the user has paid their user registration fee"`
	Version           VersionCmd           `command:"version" description:"fetch server info and CSRF token"`
	Vote              VoteCmd              `command:"vote" description:"cast ticket votes for a proposal"`
	VoteComment       VoteCommentCmd       `command:"votecomment" description:"vote on a comment"`
	VoteStatus        VoteStatusCmd        `command:"votestatus" description:"fetch the vote status of a proposal"`
}
