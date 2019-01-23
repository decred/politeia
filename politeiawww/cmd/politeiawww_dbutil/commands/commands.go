package commands

import (
	"github.com/decred/politeia/politeiawww/cmd/politeiawww_dbutil/config"
	"github.com/decred/politeia/politeiawww/database"
)

const (
	ErrorNoUserIdentity = "No user identity found.  You must login with a user."
	ErrorNoProposalFile = "You must either provide a markdown file or use the --random flag"
	ErrorBeforeAndAfter = "before and after flags cannot be used at the same time"
)

var cfg *config.Config
var db database.Database

func SetConfig(config *config.Config) {
	cfg = config
}

func SetDatabase(database database.Database) {
	db = database
}

type Cmds struct {
	AddCredits AddCreditsCmd `command:"addcredits" description:"Add the provided amount of credits to user's account"`
	SetAdmin   SetAdminCmd   `command:"setadmin" description:"Set or revoke the admin rights of a user"`
	Help       HelpCmd       `command:"help" description:"Print detailed help message of specified command"`
	DBVersion  DBVersionCmd  `command:"dbversion" description:"Print the current version of the database"`
	Dump       DumpCmd       `command:"dump" description:"Dump the database content into the specified directory"`
	Migrate    MigrateCmd    `command:"migrate" description:"Migrate the database to the newest version"`
	Import     ImportCmd     `command:"import" description:"Import a database snapshot and recreate the database from it"`
}
