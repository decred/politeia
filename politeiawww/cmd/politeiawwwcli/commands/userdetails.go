package commands

// Help message displayed for the command 'politeiawwwcli help userdetails'
var UserDetailsCmdHelpMsg = `userdetails "userid" 

Fetch user details by user id. 

Arguments:
1. userid      (string, required)   User id 

Result:
{
  "user": {
    "id":                                         (uuid.UUID)  Unique user uuid
    "email":                               (string)  Email address + lookup key
    "username":                                       (string)  Unique username
    "isadmin":                                         (bool)  Is user an admin
    "newuserpaywalladdress":              (string)  Address for paywall payment
    "newuserpaywallamount":                            (uint64)  Paywall amount
    "newuserpaywalltx":                        (string)  Paywall transaction id
    "newuserpaywalltxnotbefore":    (int64)  Txs before this time are not valid
    "newuserpaywallpollexpiry":   (int64)  Time to stop polling paywall address
    "newuserverificationtoken":       ([]byte)  Registration verification token
    "newuserverificationexpiry":  (int64)  Registration verification expiration
    "updatekeyverificationtoken":   ([]byte)  Keypair update verification token 
    "updatekeyverificationexpiry":             (int64)  Verification expiration
    "resetpasswordverificationtoken":            ([]byte)  Reset password token
    "resetpasswordverificationexpiry": (int64)  Reset password token expiration
    "lastlogintime":                 (int64)  Unix timestamp of last user login 
    "failedloginattempts": (uint64)  Number of sequential failed login attempts
    "isdeactivated":          (bool)  Whether the account is deactivated or not
    "islocked":                    (bool)  Whether the account is locked or not
    "identities": [
      {
        "pubkey":            (string)  User's public key
        "isactive":          (bool)    Whether user's identity is active or not 
      }
    ],
    "proposalcredits":       (uint64)  Number of available proposal credits
    "emailnotifications":    (uint64)  Whether to notify via emails
  }
}`

type UserDetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserDetailsCmd) Execute(args []string) error {
	udr, err := c.UserDetails(cmd.Args.UserID)
	if err != nil {
		return err
	}
	return Print(udr, cfg.Verbose, cfg.RawJSON)
}
