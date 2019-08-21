package commands

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// NewDCCUserCmd creates a new politeia user.
type NewDCCUserCmd struct {
	Args              struct{} `positional-args:"true"`
	ContractorName    string   `long:"contractorname" optional:"true" description:"The Name or identifier of the nominated user."`
	ContractorContact string   `long:"contractorcontact" optional:"true" description:"The matrix contact of the nominated user."`
	ContractorEmail   string   `long:"contractoremail" optional:"true" description:"An email address associated to the user."`
}

// Execute executes the new dcc user command.
func (cmd *NewDCCUserCmd) Execute(args []string) error {
	email := cmd.ContractorEmail
	name := cmd.ContractorName
	contact := cmd.ContractorContact

	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	if email == "" || name == "" || contact == "" {
		reader := bufio.NewReader(os.Stdin)
		if name == "" {
			fmt.Print("Enter the DCC user's name or identifier: ")
			name, _ = reader.ReadString('\n')
		}
		if email == "" {
			fmt.Print("Enter the DCC user's email: ")
			email, _ = reader.ReadString('\n')
		}
		if contact == "" {
			fmt.Print("Enter the DCC user's contact or matrix id: ")
			contact, _ = reader.ReadString('\n')
		}
		fmt.Print("\nPlease carefully review the information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue.")
		reader.ReadString('\n')
	}

	sig := cfg.Identity.SignMessage([]byte(name + contact + email))

	// Setup new user request
	ndu := cms.NewDCCUser{
		ContractorName:    strings.TrimSpace(name),
		ContractorContact: strings.TrimSpace(contact),
		ContractorEmail:   strings.TrimSpace(email),
		Signature:         hex.EncodeToString(sig[:]),
		PublicKey:         hex.EncodeToString(cfg.Identity.Public.Key[:]),
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
