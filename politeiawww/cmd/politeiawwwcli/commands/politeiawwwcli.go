package commands

import (
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type Options struct {
	// cli flags
	Host    func(string) error `long:"host" description:"politeiawww host"`
	Json    func()             `short:"j" long:"json" description:"Print JSON"`
	Verbose func()             `short:"v" long:"verbose" description:"Print request and response details"`

	// cli commands
	ActiveVotes       ActivevotesCmd       `command:"activevotes" description:"Retrieve all proposals being actively voted on"`
	AuthorizeVote     AuthorizeVoteCmd     `command:"authorizevote" description:"Authorize a proposal vote (must be proposal author)"`
	CastVotes         CastvotesCmd         `command:"castvotes" description:"Cast ticket votes for a specific proposal"`
	CensorComment     CensorCommentCmd     `command:"censorcomment" description:"(admin) censor a proposal comment"`
	ChangePassword    ChangepasswordCmd    `command:"changepassword" description:"change the password for the currently logged in user"`
	CommentsVotes     CommentsvotesCmd     `command:"commentsvotes" description:"fetch all the comments voted by the user on a proposal"`
	ChangeUsername    ChangeusernameCmd    `command:"changeusername" description:"change the username for the currently logged in user"`
	EditProposal      EditProposalCmd      `command:"editproposal" description:"edit a proposal"`
	EditUser          EdituserCmd          `command:"edituser" description:"edit the details for the given user id"`
	GetComments       GetcommentsCmd       `command:"getcomments" description:"fetch a proposal's comments"`
	GetProposal       GetproposalCmd       `command:"getproposal" description:"fetch a proposal"`
	GetUnvetted       GetunvettedCmd       `command:"getunvetted" description:"fetch unvetted proposals"`
	GetVetted         GetvettedCmd         `command:"getvetted" description:"fetch vetted proposals"`
	Login             LoginCmd             `command:"login" description:"login to Politeia"`
	Logout            LogoutCmd            `command:"logout" description:"logout of Politeia"`
	Me                MeCmd                `command:"me" description:"return the user information of the currently logged in user"`
	NewProposal       NewproposalCmd       `command:"newproposal" description:"submit a new proposal to Politeia"`
	NewComment        NewcommentCmd        `command:"newcomment" description:"comment on a proposal"`
	NewUser           NewuserCmd           `command:"newuser" description:"create a new Politeia user"`
	Faucet            FaucetCmd            `command:"faucet" description:"use the Decred testnet faucet to send DCR to an address"`
	Policy            PolicyCmd            `command:"policy" description:"fetch server policy"`
	ProposalPaywall   ProposalpaywallCmd   `command:"proposalpaywall" description:"fetch proposal paywall details"`
	ProposalVotes     ProposalvotesCmd     `command:"proposalvotes" description:"fetch vote results for a specific proposal"`
	ResetPassword     ResetpasswordCmd     `command:"resetpassword" description:"change the password for a user that is not currently logged in"`
	Secret            SecretCmd            `command:"secret"`
	SetProposalStatus SetproposalstatusCmd `command:"setproposalstatus" description:"(admin only) set the status of a proposal"`
	StartVote         StartvoteCmd         `command:"startvote" description:"(admin only) start the voting period on a proposal"`
	UsernamesById     UsernamesbyidCmd     `command:"usernamesbyid" description:"fetch usernames by their user ids"`
	UserDetails       UserdetailsCmd       `command:"userdetails" description:"fetch a user's details by his user id"`
	UserProposals     UserproposalsCmd     `command:"userproposals" description:"fetch all proposals submitted by a specific user"`
	VerifyUser        VerifyuserCmd        `command:"verifyuser" description:"verify user's email address"`
	VerifyUserPayment VerifyuserpaymentCmd `command:"verifyuserpayment" description:"check if the user has paid their user registration fee"`
	Version           VersionCmd           `command:"version" description:"fetch server info and CSRF token"`
	VoteComment       VotecommentCmd       `command:"votecomment" description:"vote on a comment"`
	VoteStatus        VoteStatusCmd        `command:"votestatus" description:"fetch the vote status of a proposal"`
}

// registers callbacks for cli flags
func RegisterCallbacks() {
	Opts.Host = func(host string) error {
		err := config.SetHost(host)
		if err != nil {
			return err
		}
		Ctx.SetCookies(host, config.Cookies)
		Ctx.SetCsrf(config.CsrfToken)
		return nil
	}

	Opts.Json = func() {
		config.PrintJSON = true
	}

	Opts.Verbose = func() {
		config.Verbose = true
	}
}

var Opts Options
var Ctx *client.Ctx
