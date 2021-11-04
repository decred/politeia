// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/util"
)

const (
	defaultTlogHost    = "localhost:8090"
	defaultTlogPass    = "tlogpass"
	defaultDBType      = "mysql"
	defaultDBHost      = "localhost:3306"
	defaultDBPass      = "politeiadpass"
	defaultDataDirname = "data"
)

var (
	defaultHomeDir  = dcrutil.AppDataDir("politeiad", false)
	defaultDataDir  = filepath.Join(defaultHomeDir, defaultDataDirname)
	activeNetParams = &params{
		Params:              chaincfg.TestNet3Params(),
		WalletRPCServerPort: "9111",
	}

	// Dump command & flags.
	cmdDump     = flag.NewFlagSet("dump", flag.ContinueOnError)
	cmdDumpPath = cmdDump.String("path", "", "path to git repo")
	cmdDumpOut  = cmdDump.String("out", "", "path to dump data")
	cmdDumpTest = cmdDump.Bool("test", false, "test mode")

	// User prompted flags used for testing.
	cmdDumpUserID      string
	cmdDumpBallotCount int

	// Import command & flags.
	cmdImport     = flag.NewFlagSet("import", flag.ContinueOnError)
	cmdImportPath = cmdImport.String("path", "", "path to dumped data")

	// Config flags for tstore.
	tlogHost = flag.String("tloghost", defaultTlogHost, "tlog host")
	tlogPass = flag.String("tlogpass", defaultTlogPass, "tlog pass")
	dbHost   = flag.String("dbhost", defaultDBHost, "mysql DB host")
	dbPass   = flag.String("dbpass", defaultDBPass, "mysql DB pass")
)

type legacy struct {
	sync.RWMutex
	tstore *tstore.Tstore
	client *http.Client

	// comments is a cache used for feeding the parentID data to the
	// comment del metadata payload.
	comments map[string]map[string]decredplugin.Comment // [newToken][commentid]comment

	// queue holds the RFP submission records data that needs to be parsed
	// last, when their respective RFP parent has already been inserted.
	queue []parsedData

	// tokens is a cache that maps legacy tokens to new tlog tokens, and
	// is used to get the new token from a legacy RFP proposal for their
	// submissions and feed the LinkTo metadata field.
	tokens map[string]string // [legacyToken]newToken

	// rfpParents holds the startRunoffRecord blob of each RFP parent to be
	// saved at a later stage of the parsing.
	rfpParents map[string]*startRunoffRecord

	// versions holds a cache for the record latest version being parsed.
	versions map[string]int // [legacyToken]version

	// ts holds the cast vote timestamps for each record, parsed through git.
	timestamps map[string]map[string]int64 // [legacyToken][ticket]timestamp
}

// newLegacyImport returns an initialized legacyImport with an open tstore
// connection and client http.
func newLegacy() (*legacy, error) {
	ts, err := tstore.New(defaultHomeDir, defaultDataDir, activeNetParams.Params,
		*tlogHost, *tlogPass, defaultDBType, *dbHost, *dbPass,
		v1.DefaultTestnetTimeHost,
		"")
	if err != nil {
		return nil, err
	}

	c, err := util.NewHTTPClient(false, "")
	if err != nil {
		return nil, err
	}

	return &legacy{
		tstore:     ts,
		client:     c,
		comments:   make(map[string]map[string]decredplugin.Comment),
		tokens:     make(map[string]string),
		rfpParents: make(map[string]*startRunoffRecord),
		versions:   make(map[string]int),
		timestamps: make(map[string]map[string]int64),
	}, nil
}

func _main() error {
	fmt.Println("legacy: Start!")

	fmt.Println("legacy: Opening connection with tstore")

	l, err := newLegacy()
	if err != nil {
		return err
	}

	switch os.Args[1] {
	case "dump":
		err := l.handleDumpCmd()
		if err != nil {
			return err
		}
	case "import":
		err := l.handleImportCmd()
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("legacy: Invalid command, please refer to docs")
	}

	return nil
}

func (l *legacy) handleDumpCmd() error {
	fmt.Println("legacy: Executing dump command")

	cmdDump.Parse(os.Args[2:])

	path := util.CleanAndExpandPath(*cmdDumpPath)
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	if *cmdDumpTest {
		fmt.Println("legacy: Running on test mode")

		fmt.Print("\n")
		fmt.Println("legacy: Enter a userid from your local db")
		fmt.Print(" > ")
		fmt.Scanln(&cmdDumpUserID)
		fmt.Print("\n")

		fmt.Println("legacy: Enter how many votes to parse from the ballot " +
			"journal")
		fmt.Println("        (this is an expensive process that takes time, " +
			"limit to a few while testing)")
		fmt.Print(" > ")
		fmt.Scanln(&cmdDumpBallotCount)
		fmt.Print("\n")

	}
	err = l.cmdDump(path)
	if err != nil {
		return err
	}

	fmt.Println("legacy: Dump done!")

	return nil
}

func (l *legacy) handleImportCmd() error {
	fmt.Println("legacy: Executing import command")

	cmdImport.Parse(os.Args[2:])

	path := util.CleanAndExpandPath(*cmdImportPath)
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	err = l.cmdImport(path)
	if err != nil {
		return err
	}

	fmt.Println("legacy: Import done!")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
