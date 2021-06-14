package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// AddCreditsCmd adds credits to the given user
type AddCreditsCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
		Quantity string `positional-arg-name:"quantity"`
	} `positional-args:"true" required:"true"`
}

// Execute addcredits command
func (cmd *AddCreditsCmd) Execute(args []string) error {
	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	username := cmd.Args.Username
	quantity, err := strconv.Atoi(cmd.Args.Quantity)
	if err != nil {
		return fmt.Errorf("parse int '%v' failed: %v",
			cmd.Args.Quantity, err)
	}
	// Lookup user
	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	// Create proposal credits
	ts := time.Now().Unix()
	c := make([]user.ProposalCredit, 0, quantity)
	for i := 0; i < quantity; i++ {
		c = append(c, user.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: ts,
			TxID:          "created_by_dbutil",
		})
	}
	u.UnspentProposalCredits = append(u.UnspentProposalCredits, c...)

	// Update database
	err = userDB.UserUpdate(*u)
	if err != nil {
		return fmt.Errorf("update user: %v", err)
	}

	fmt.Printf("%v proposal credits added to account %v\n",
		quantity, username)

	return nil
}

// addCreditsHelpMsg is the output of the help command when 'addcredits' is
// specified.
const addCreditsHelpMsg = `addcredits --database=<database> "username" quantity 

Adds the quantity of user credits to given username's account.
This command requires a DB connection. You can use either 'leveldb' or
'cockroachdb'.

Arguments:
1. username      (string, required)   User username
2. quantity      (string, required)   Amount of proposal credits 
`
