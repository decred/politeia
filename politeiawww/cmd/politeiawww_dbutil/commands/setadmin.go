package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/database"
)

const SetAdminCmdHelpMsg = `setadmin "userid" (true/false)`

type SetAdminCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" required:"true" description:"User ID to be set or revoked the admin rights"`
		Enable bool   `positional-arg-name:"enable" required:"true" description:" Set user as admin (true) or revoke the admin rights (false)"`
	} `positional-args:"true"`
}

func (cmd *SetAdminCmd) Execute(args []string) error {
	userid := cmd.Args.UserID
	enable := cmd.Args.Enable

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

	// Check if the action is consistent with the current user access level.
	if user.Admin && enable {
		return fmt.Errorf("User access cannot be upgraded because he is already" +
			" an admin")
	}
	if !user.Admin && !enable {
		return fmt.Errorf("User access cannot be deprecated because he is not" +
			" an admin")
	}

	// Update user admin level
	user.Admin = enable

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

	if enable {
		fmt.Printf("User with ID %v elevated to admin\n", userid)
	} else {
		fmt.Printf("User with ID %v removed from admin\n", userid)
	}

	return nil
}
