package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	verify = false // Validate server TLS certificate
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeiavoter [flags] <action> [arguments]\n")
	fmt.Fprintf(os.Stderr, " flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n actions:\n")
	fmt.Fprintf(os.Stderr, "  inventory          - Retrieve active "+
		"votes\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func inventory() error {
	return fmt.Errorf("implement inventory please")
}

func _main() error {
	cfg, args, err := loadConfig()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}
	_ = cfg

	// Scan through command line arguments.
	for i, a := range flag.Args() {
		// Select action
		if i == 0 {
			switch a {
			case "inventory":
				return inventory()
			default:
				return fmt.Errorf("invalid action: %v", a)
			}
		}
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
