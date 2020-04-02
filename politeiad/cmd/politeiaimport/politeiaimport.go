// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/chaincfg"
	"github.com/thi4go/politeia/politeiad/backend/gitbe"
	"github.com/thi4go/politeia/politeiad/sharedconfig"
	"github.com/thi4go/politeia/util"
)

const (
	defaultDataDirname     = sharedconfig.DefaultDataDirname
	defaultUnvettedDirname = gitbe.DefaultUnvettedPath
	defaultVettedDirname   = gitbe.DefaultVettedPath
	defaultJournalsDirname = gitbe.DefaultJournalsPath
)

var (
	defaultHomeDir = sharedconfig.DefaultHomeDir

	// CLI flags
	homeDir = flag.String("homedir", defaultHomeDir, "politeiad home dir path")
	testnet = flag.Bool("testnet", false, "import data is testnet data")
)

func _main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("must provide import directory")
	}

	// Parse import directory
	importDir := util.CleanAndExpandPath(flag.Arg(0))
	_, err := os.Stat(importDir)
	if err != nil {
		return err
	}

	// Set data directory
	activeNet := chaincfg.MainNetParams.Name
	if *testnet {
		activeNet = chaincfg.TestNet3Params.Name
	}

	dataDir := filepath.Join(util.CleanAndExpandPath(*homeDir),
		defaultDataDirname, activeNet)

	// Get confirmation from the user that it's
	// ok to delete the current data directory.
	_, err = os.Stat(dataDir)
	if err == nil {
		r := bufio.NewReader(os.Stdin)

		fmt.Printf("You are about to delete     : %v\n", dataDir)
		fmt.Printf("It will be replaced with    : %v\n", importDir)
		fmt.Printf("Continue? (n/no/y/yes) [no] : ")

		input, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		i := strings.ToLower(strings.TrimSuffix(input, "\n"))
		if i != "y" && i != "yes" {
			fmt.Printf("Exiting\n")
			return nil
		}
	}

	journalsPath := filepath.Join(dataDir, defaultJournalsDirname)
	unvettedPath := filepath.Join(dataDir, defaultUnvettedDirname)
	vettedPath := filepath.Join(dataDir, defaultVettedDirname)

	// Remove existing data dir
	err = os.RemoveAll(journalsPath)
	if err != nil {
		return err
	}

	err = os.RemoveAll(unvettedPath)
	if err != nil {
		return err
	}

	err = os.RemoveAll(vettedPath)
	if err != nil {
		return err
	}

	fmt.Printf("Walking import directory...\n")

	// Walk import directory and copy all relevant files over
	// to the unvetted, vetted, and journal directories.
	err = filepath.Walk(importDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Get the file's parent directory path relative to
			// the import directory.
			r, err := filepath.Rel(importDir, filepath.Dir(path))
			if err != nil {
				return err
			}

			// Make sure the full parent directory path
			// exists for both unvetted and vetted dirs.
			u := filepath.Join(unvettedPath, r)
			err = os.MkdirAll(u, 0774)
			if err != nil {
				return err
			}

			v := filepath.Join(vettedPath, r)
			err = os.MkdirAll(v, 0774)
			if err != nil {
				return err
			}

			// Copy file to unvetted and vetted
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			uf := filepath.Join(u, info.Name())
			err = ioutil.WriteFile(uf, b, 0774)
			if err != nil {
				return err
			}

			vf := filepath.Join(v, info.Name())
			err = ioutil.WriteFile(vf, b, 0774)
			if err != nil {
				return err
			}

			// Check if the file is a journal
			if !strings.HasSuffix(info.Name(), ".journal") {
				// Not a journal; continue to next file
				return nil
			}

			// Copy journal to the journals directory. Note that
			// the journals use a different directory structure
			// then unvetted/vetted.
			//
			// unvetted/[token]/plugin/decred/comments.journal
			// journals/[token]/comments.journal

			// Parse token dirname
			var token string
			dirs := strings.Split(r, "/")
			for _, v := range dirs {
				_, err = util.ConvertStringToken(v)
				if err == nil {
					token = v
				}
			}

			// Copy journal
			j := filepath.Join(journalsPath, token)
			err = os.MkdirAll(j, 0774)
			if err != nil {
				return err
			}

			jf := filepath.Join(j, info.Name())
			err = ioutil.WriteFile(jf, b, 0774)
			if err != nil {
				return err
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	fmt.Printf("Done!\n")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
