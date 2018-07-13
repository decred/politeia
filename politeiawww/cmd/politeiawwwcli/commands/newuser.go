package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

type NewuserCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Username string `positional-arg-name:"username"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" optional:"true"`
	Random        bool   `long:"random" optional:"true" description:"Generate a random email/password for the user"`
	Verify        bool   `long:"verify" optional:"true" description:"Verify the user's email address"`
	Paywall       bool   `long:"paywall" optional:"true" description:"Satisfy paywall fee using testnet faucet"`
	OverrideToken string `long:"overridetoken" optional:"true" description:"Override token for the testnet faucet"`
}

func (cmd *NewuserCmd) Execute(args []string) error {
	if !cmd.Random && cmd.Args.Email == "" {
		return fmt.Errorf("You must either provide an email, username & " +
			"password or use the --random flag")
	}

	// fetch Politeia policy for password requirements
	pr, err := Ctx.Policy()
	if err != nil {
		return err
	}

	// assign email/password
	var email string
	var username string
	var password string

	if cmd.Random {
		b, err := util.Random(int(pr.MinPasswordLength))
		if err != nil {
			return err
		}

		email = hex.EncodeToString(b) + "@example.com"
		username = hex.EncodeToString(b)
		password = hex.EncodeToString(b)
	} else {
		email = cmd.Args.Email
		username = cmd.Args.Username
		password = cmd.Args.Password
	}

	// create new user
	token, id, paywallAddress, paywallAmount, err := Ctx.NewUser(email,
		username, password)
	if err != nil {
		return err
	}

	// verify user's email address
	if cmd.Verify {
		config.UserIdentity = id
		verifyCmd := VerifyuserCmd{
			Args: VerifyuserArgs{
				Email: email,
				Token: token,
			},
		}

		err = verifyCmd.Execute(nil)
		if err != nil {
			return err
		}
	}

	// satisfy paywall fee using testnet faucet
	if cmd.Paywall {
		faucetCmd := FaucetCmd{
			Args: FaucetArgs{
				Amount:  paywallAmount,
				Address: paywallAddress,
			},
			OverrideToken: cmd.OverrideToken,
		}

		err = faucetCmd.Execute(nil)
		if err != nil {
			return err
		}
	}

	return nil
}
