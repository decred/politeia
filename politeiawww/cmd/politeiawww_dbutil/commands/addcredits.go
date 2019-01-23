package commands

import (
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/politeiawww/database"
)

const AddCreditsCmdHelpMsg = `addcredits "userid" "amount"`

type AddCreditsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" required:"true" description:"User ID to be given the credits"`
		Amount string `positional-arg-name:"amount" required:"true" description:"Amount of proposals credits"`
	} `positional-args:"true"`
}

func (cmd *AddCreditsCmd) Execute(args []string) error {
	userid := cmd.Args.UserID

	amount, err := strconv.Atoi(cmd.Args.Amount)
	if err != nil {
		return fmt.Errorf("amount must parse to an int")
	}

	// Try to get user from database using the provided id.
	p, err := db.Get(userid)
	if err == database.ErrNotFound {
		return fmt.Errorf("User not found in the database: %v", userid)
	}
	if err != nil {
		return fmt.Errorf("Get user: %v", err)
	}

	// Decode user
	user, err := database.DecodeUser(p)
	if err != nil {
		return fmt.Errorf("Decode user: %v", err)
	}

	// Create proposal credits.
	c := make([]database.ProposalCredit, amount)
	timestamp := time.Now().Unix()
	for i := 0; i < amount; i++ {
		c[i] = database.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: timestamp,
			TxID:          "created_by_dbutil",
		}
	}
	user.UnspentProposalCredits = append(user.UnspentProposalCredits, c...)

	// Encode user.
	p, err = database.EncodeUser(*user)
	if err != nil {
		return fmt.Errorf("Encode user: %v", err)
	}

	// Update the user record in the database.
	err = db.Put(userid, p)
	if err != nil {
		return fmt.Errorf("Put user: %v", err)
	}

	fmt.Printf("%v proposal credits added to user with ID %v account\n", amount, userid)
	return nil
}
