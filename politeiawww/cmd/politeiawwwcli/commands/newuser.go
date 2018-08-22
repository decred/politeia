package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

type NewUserCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Username string `positional-arg-name:"username"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" optional:"true"`
	Random  bool `long:"random" optional:"true" description:"Generate a random email/password for the user"`
	Verify  bool `long:"verify" optional:"true" description:"Verify the user's email address"`
	Paywall bool `long:"paywall" optional:"true" description:"Satisfy paywall fee using testnet faucet"`
}

func (cmd *NewUserCmd) Execute(args []string) error {
	email := cmd.Args.Email
	username := cmd.Args.Username
	password := cmd.Args.Password

	if !cmd.Random && (email == "" || username == "" || password == "") {
		return fmt.Errorf("invalid credentials: you must either specify user " +
			"credentials (email, username, password) or use the --random flag")
	}

	// Fetch CSRF tokens
	_, err := c.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	// Fetch  policy for password requirements
	pr, err := c.Policy()
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

	// Create user identity
	// XXX: We are using the email to generate the identity
	id, err := IdentityFromString(email)
	if err != nil {
		return err
	}

	// Setup new user request
	nu := &v1.NewUser{
		Email:     email,
		Username:  username,
		Password:  DigestSHA3(password),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	// Print request details
	err = Print(nu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	nur, err := c.NewUser(nu)
	if err != nil {
		return fmt.Errorf("NewUser: %v", err)
	}

	// Print response details
	err = Print(nur, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Verify user's email address
	if cmd.Verify {
		sig := id.SignMessage([]byte(nur.VerificationToken))
		vnur, err := c.VerifyNewUser(&v1.VerifyNewUser{
			Email:             email,
			VerificationToken: nur.VerificationToken,
			Signature:         hex.EncodeToString(sig[:]),
		})
		if err != nil {
			return fmt.Errorf("VerifyNewUser: %v", err)
		}

		err = Print(vnur, cfg.Verbose, cfg.RawJSON)
		if err != nil {
			return err
		}
	}

	// Satisfy paywall fee using testnet faucet
	if cmd.Paywall {
		faucet := FaucetCmd{}
		faucet.Args.Address = nur.PaywallAddress
		faucet.Args.Amount = nur.PaywallAmount
		err := faucet.Execute(nil)
		if err != nil {
			return err
		}
	}

	return nil
}
