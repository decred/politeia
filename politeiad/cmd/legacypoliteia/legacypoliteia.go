// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	// Command names. See the usage.go file for details on command usage.
	convertCmdName = "convert"
	importCmdName  = "import"
)

func _main() error {
	// Parse the CLI args
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Execute the specified command
	switch args[0] {
	case convertCmdName:
		return execConvertCmd(args[1:])
	case importCmdName:
		return execImportCmd(args[1:])
	default:
		return fmt.Errorf("command '%v' not found", args[0])
	}
}

func main() {
	// Use a custom help message
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMsg)
	}
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
