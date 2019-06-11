package commands

import (
	"fmt"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// NewUserCmd creates a new politeia user.
type NewDCCUserCmd struct {
	Args struct {
		ContractorName    string `positional-arg-name:"name"`    // Email address
		ContractorContact string `positional-arg-name:"contact"` // Email address
		ContractorEmail   string `positional-arg-name:"email"`   // Email address
	} `positional-args:"true"`
}

// Execute executes the new dcc user command.
func (cmd *NewDCCUserCmd) Execute(args []string) error {
	email := cmd.Args.ContractorEmail
	name := cmd.Args.ContractorName
	contact := cmd.Args.ContractorContact

	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	// Setup new user request
	ndu := cms.NewDCCUser{
		ContractorName:    name,
		ContractorContact: contact,
		ContractorEmail:   email,
	}

	// Print request details
	err = printJSON(ndu)
	if err != nil {
		return err
	}

	// Send request
	ndur, err := client.NewDCCUser(ndu)
	if err != nil {
		return fmt.Errorf("NewUser: %v", err)
	}

	// Print response details
	err = printJSON(ndur)
	if err != nil {
		return err
	}

	return nil
}
