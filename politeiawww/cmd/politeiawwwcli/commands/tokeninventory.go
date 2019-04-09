package commands

// TokenInventory retrieves the censorship record tokens of all proposals in
// the inventory.
type TokenInventoryCmd struct{}

// Execute executes the token inventory command.
func (cmd *TokenInventoryCmd) Execute(args []string) error {
	reply, err := client.TokenInventory()
	if err != nil {
		return err
	}
	return printJSON(reply)
}
