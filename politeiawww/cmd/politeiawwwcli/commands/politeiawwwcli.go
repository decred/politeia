package commands

import (
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type Options struct {
	// cli flags
	Host func(string) error `long:"host" description:"politeiawww host"`
	Json func()             `short:"j" long:"json" description:"Print JSON"`

	// cli commands
	ChangePassword    ChangepasswordCmd    `command:"changepassword" description:"change the password for the currently logged in user"`
	ChangeUsername    ChangeusernameCmd    `command:"changeusername" description:"change the username for the currently logged in user"`
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
	ResetPassword     ResetpasswordCmd     `command:"resetpassword" description:"change the password for a user that is not currently logged in"`
	Secret            SecretCmd            `command:"secret"`
	SetProposalStatus SetproposalstatusCmd `command:"setproposalstatus" description:"(admin only) set the status of a proposal"`
	StartVote         StartvoteCmd         `command:"startvote" description:"(admin only) start the voting period on a proposal"`
	UpdateUserKey     UpdateuserkeyCmd     `command:"updateuserkey" description:"update the user identity saved to appDataDir"`
	UserProposals     UserproposalsCmd     `command:"userproposals" description:"fetch all proposals submitted by a specific user"`
	VerifyUser        VerifyuserCmd        `command:"verifyuser" description:"verify user's email address"`
	VerifyUserPayment VerifyuserpaymentCmd `command:"verifyuserpayment" description:"check if the user has paid their user registration fee"`
	Version           VersionCmd           `command:"version" description:"fetch server info and CSRF token"`
}

// registers callbacks for cli flags
func RegisterCallbacks() {
	Opts.Host = func(host string) error {
		err := config.UpdateHost(host)
		if err != nil {
			return err
		}

		Ctx.SetCookies(host, config.Cookies)
		return nil
	}

	Opts.Json = func() {
		config.PrintJson = true
	}
}

var Opts Options
var Ctx *client.Ctx
