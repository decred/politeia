// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

const (
	// Config settings
	defaultHomeDirname    = "cmsctl"
	defaultDataDirname    = "data"
	defaultConfigFilename = "cmsctl.conf"
)

var (
	// Global variables for cmsctl commands
	cfg    *shared.Config
	client *shared.Client

	// Config settings
	defaultHomeDir = dcrutil.AppDataDir(defaultHomeDirname, false)
)

type cmsctl struct {
	// This is here to prevent parsing errors caused by config flags.
	Config shared.Config

	// Basic commands
	Help cmdHelp `command:"help"`

	// Server commands
	Version shared.VersionCmd `command:"version"`
	Policy  policyCmd         `command:"policy"`
	Login   shared.LoginCmd   `command:"login"`
	Logout  shared.LogoutCmd  `command:"logout"`
	Me      shared.MeCmd      `command:"me"`

	// User commands
	UserInvite   cmdUserInvite   `command:"userinvite"`
	UserRegister cmdUserRegister `command:"userregister"`
	UserManage   cmdUserManage   `command:"usermanage"`

	// Invoice commands
	InvoicePolicy    cmdInvoicePolicy    `command:"invoicepolicy"`
	InvoiceNew       cmdInvoiceNew       `command:"invoicenew"`
	InvoiceDetails   cmdInvoiceDetails   `command:"invoicedetails"`
	InvoiceEdit      cmdInvoiceEdit      `command:"invoiceedit"`
	InvoiceSetStatus cmdInvoiceSetStatus `command:"invoicesetstatus"`

	// Records commands
	RecordPolicy cmdRecordPolicy `command:"recordpolicy"`

	// Comments commands

	TestRun cmdTestRun `command:"testrun"`
}

const helpMsg = `Application Options:
      --appdata=    Path to application home directory
      --host=       politeiawww host
  -j, --json        Print raw JSON output
      --version     Display version information and exit
      --skipverify  Skip verifying the server's certificate chain and host name
  -v, --verbose     Print verbose output
      --silent      Suppress all output

Help commands
  help                         Print detailed help message for a command

Basic commands
  version                      (public) Get politeiawww server version and CSRF
  policy                       (public) Get politeiawww server policy
  secret                       (public) Ping the server
  login                        (public) Login to politeiawww
  logout                       (user)   Logout from politeiawww
  me                           (user)   Get details of the logged in user

User commands
  userinvite                   (admin) Invite a new contractor
  userregister                 (public) Register an invited user

Invoice commands
  invoicepolicy                (public) Get the cms api policy
  invoicenew                   (user)   Submit a new invoice
  invoiceedit                  (user)   Edit an existing invoice
  invoicedetails               (user)   Request invoice details

Record commands
  recordpolicy                 (public) Get the records api policy

Comment commands
  commentpolicy                (public) Get the comments api policy
  commentnew                   (user)   Submit a new comment
  commentvote                  (user)   Upvote/downvote a comment
  commentcensor                (admin)  Censor a comment
  commentcount                 (public) Get the number of comments
  comments                     (public) Get comments
  commentvotes                 (public) Get comment votes
  commenttimestamps            (public) Get comment timestamps

Websocket commands
  subscribe                    (public) Subscribe/unsubscribe to websocket event

`

func _main() error {
	// Load config. The config variable is aglobal variable.
	var err error
	cfg, err = shared.LoadConfig(defaultHomeDir,
		defaultDataDirname, defaultConfigFilename)
	if err != nil {
		return fmt.Errorf("load config: %v", err)
	}

	// Load client. The client variable is a global variable.
	client, err = shared.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("load client: %v", err)
	}

	// Setup global variables for shared commands
	shared.SetConfig(cfg)
	shared.SetClient(client)

	// Check for a help flag. This is done separately so that we can
	// print our own custom help message.
	var opts flags.Options = flags.HelpFlag | flags.IgnoreUnknown |
		flags.PassDoubleDash
	parser := flags.NewParser(&struct{}{}, opts)
	_, err = parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			// The -h, --help flag was used. Print the custom help message
			// and exit gracefully.
			fmt.Printf("%v\n", helpMsg)
			os.Exit(0)
		}
		return fmt.Errorf("parse help flag: %v", err)
	}

	// Parse CLI args and execute command
	parser = flags.NewParser(&cmsctl{Config: *cfg}, flags.Default)
	_, err = parser.Parse()
	if err != nil {
		// An error has occurred during command execution. go-flags will
		// have already printed the error to os.Stdout. Exit with an
		// error code.
		os.Exit(1)
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
