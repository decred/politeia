package main

import (
	"fmt"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/commands"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

func main() {
	err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// create new http client
	commands.Ctx, err = client.NewClient(true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// configure client to use any previously saved cookies
	if len(config.Cookies) != 0 {
		commands.Ctx.SetCookies(config.Host, config.Cookies)
	}

	// setup and run cli parser
	commands.RegisterCallbacks()
	var parser = flags.NewParser(&commands.Opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
}
