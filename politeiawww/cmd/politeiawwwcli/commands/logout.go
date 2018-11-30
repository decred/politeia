package commands

// Help message displayed for the command 'politeiawwwcli help logout'
var LogoutCmdHelpMsg = `logout 

Logout as a user or admin.

Arguments:
None

Result:
{}`

type LogoutCmd struct{}

func (cmd *LogoutCmd) Execute(args []string) error {
	lr, err := c.Logout()
	if err != nil {
		return err
	}
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
