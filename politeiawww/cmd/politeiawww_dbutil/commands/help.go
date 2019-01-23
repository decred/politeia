package commands

import "fmt"

type HelpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic" description:"get information about available commands"`
	} `positional-args:"true"  required:"true"`
}

func (cmd *HelpCmd) Execute(args []string) error {

	switch cmd.Args.Topic {
	case "setadmin":
		fmt.Printf("%s\n", SetAdminCmdHelpMsg)
	case "addcredits":
		fmt.Printf("%s\n", AddCreditsCmdHelpMsg)
	case "dbversion":
		fmt.Printf("%s\n", DBVersionHelpMsg)
	case "dump":
		fmt.Printf("%s\n", ImportHelpMsg)
	case "migrate":
		fmt.Printf("%s\n", MigrateHelpMsg)
	default:
		fmt.Printf("invalid command\n")
	}

	return nil
}
