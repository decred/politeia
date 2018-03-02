package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/util"
)

var (
	testnet = flag.Bool("testnet", false, "Use testnet port")
	verbose = flag.Bool("v", false, "Verbose")
	rpcuser = flag.String("rpcuser", "", "RPC user name for privileged calls")
	rpcpass = flag.String("rpcpass", "", "RPC password for privileged calls")
	rpchost = flag.String("rpchost", "", "RPC host")
	rpccert = flag.String("rpccert", "", "RPC certificate")
	verify  = false // Validate server TLS certificate
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia [flags] <action> [arguments]\n")
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
	flag.Parse()
	if len(flag.Args()) == 0 {
		usage()
		return fmt.Errorf("must provide action")
	}

	if *rpchost == "" {
		if *testnet {
			*rpchost = v1.DefaultTestnetHost
		} else {
			*rpchost = v1.DefaultMainnetHost
		}
	} else {
		// For now assume we can't verify server TLS certificate
		verify = true
	}

	port := v1.DefaultMainnetPort
	if *testnet {
		port = v1.DefaultTestnetPort
	}

	*rpchost = util.NormalizeAddress(*rpchost, port)

	// Set port if not specified.
	u, err := url.Parse("https://" + *rpchost)
	if err != nil {
		return err
	}
	*rpchost = u.String()

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
