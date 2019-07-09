package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// NewUserCmd creates a new politeia user.
type NewUserCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`    // Email address
		Username string `positional-arg-name:"username"` // Username
		Password string `positional-arg-name:"password"` // Password
	} `positional-args:"true"`
	Random  bool `long:"random" optional:"true"`  // Generate random user credentials
	Paywall bool `long:"paywall" optional:"true"` // Use faucet to pay paywall (tesnet only)
	Verify  bool `long:"verify" optional:"true"`  // Verify user email address (testnet only)
	NoSave  bool `long:"nosave" optional:"true"`  // Don't save user identity to disk
}

// Execute executes the new user command.
func (cmd *NewUserCmd) Execute(args []string) error {
	email := cmd.Args.Email
	username := cmd.Args.Username
	password := cmd.Args.Password

	if !cmd.Random && (email == "" || username == "" || password == "") {
		return fmt.Errorf("invalid credentials: you must either specify user " +
			"credentials (email, username, password) or use the --random flag")
	}

	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	// Fetch  policy for password requirements
	pr, err := client.Policy()
	if err != nil {
		return fmt.Errorf("Policy: %v", err)
	}

	// Create new user credentials if required
	if cmd.Random {
		b, err := util.Random(int(pr.MinPasswordLength))
		if err != nil {
			return err
		}

		email = hex.EncodeToString(b) + "@example.com"
		username = hex.EncodeToString(b)
		password = hex.EncodeToString(b)
	}

	// Validate password
	if uint(len(password)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// Create user identity and save it to disk
	id, err := newIdentity()
	if err != nil {
		return err
	}

	// Setup new user request
	nu := &v1.NewUser{
		Email:     email,
		Username:  username,
		Password:  digestSHA3(password),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	// Print request details
	err = printJSON(nu)
	if err != nil {
		return err
	}

	// Send request
	nur, err := client.NewUser(nu)
	if err != nil {
		return fmt.Errorf("NewUser: %v", err)
	}

	// Save user identity to disk
	if !cmd.NoSave {
		err = cfg.SaveIdentity(nu.Username, id)
		if err != nil {
			return err
		}
	}

	// Print response details
	err = printJSON(nur)
	if err != nil {
		return err
	}

	// Verify user's email address
	if cmd.Verify {
		sig := id.SignMessage([]byte(nur.VerificationToken))
		vnur, err := client.VerifyNewUser(&v1.VerifyNewUser{
			Email:             email,
			VerificationToken: nur.VerificationToken,
			Signature:         hex.EncodeToString(sig[:]),
		})
		if err != nil {
			return fmt.Errorf("VerifyNewUser: %v", err)
		}

		err = printJSON(vnur)
		if err != nil {
			return err
		}
	}

	// Login to politeia
	l := &v1.Login{
		Username: username,
		Password: digestSHA3(password),
	}

	lr, err := client.Login(l)
	if err != nil {
		return err
	}

	// Pays paywall fee using faucet
	if cmd.Paywall {
		faucet := SendFaucetTxCmd{}
		faucet.Args.Address = lr.PaywallAddress
		faucet.Args.Amount = lr.PaywallAmount
		err = faucet.Execute(nil)
		if err != nil {
			return err
		}
	}

	return nil
}

// newUserHelpMsg is the output of the help command when 'newuser' is
// specified.
const newUserHelpMsg = `newuser [flags] "email" "username" "password" 

Create a new Politeia user. Users can be created by supplying all the arguments
below, or supplying the --random flag. If --random is used, Politeia will 
generate a random email, username and password.

Arguments:
1. email      (string, required)   Email address
2. username   (string, required)   Username 
3. password   (string, required)   Password

Flags:
  --random    (bool, optional)   Generate a random email/password for the user
  --paywall   (bool, optional)   Satisfy the paywall fee using testnet faucet
  --verify    (bool, optional)   Verify the user's email address
  --nosave    (bool, optional)   Do not save the user identity to disk 

Request:
{
  "email":      (string)  User email
  "password":   (string)  Password
  "publickey":  (string)  Active public key
  "username":   (string)  Username
}

Response:
{
  "verificationtoken":   (string)  Server verification token
}`
