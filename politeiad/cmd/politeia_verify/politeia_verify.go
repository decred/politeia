// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/agl/ed25519"
	"github.com/decred/dcrtime/merkle"
)

var (
	publicKeyFlag = flag.String("k", "", "server public key")
	tokenFlag     = flag.String("t", "", "record censorship token")
	signatureFlag = flag.String("s", "", "record censorship signature")
	verboseFlag   = flag.Bool("v", false, "verbose output")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia_verify [-v] -k <pubkey> -t <token> -s <signature> <filename>...\n")
	fmt.Fprintf(os.Stderr, " parameters:\n")
	fmt.Fprintf(os.Stderr, "  pubkey        - Politiea's public server key\n")
	fmt.Fprintf(os.Stderr, "  token         - Record censorship token\n")
	fmt.Fprintf(os.Stderr, "  signature     - Record censorship "+
		"signature\n")
	fmt.Fprintf(os.Stderr, "  v             - Verbose output\n")
	fmt.Fprintf(os.Stderr, "  filename      - One or more paths to the markdown "+
		"and image files that make up the record\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func verifyRecord(key [ed25519.PublicKeySize]byte, token []byte, signature [ed25519.SignatureSize]byte) error {
	flags := flag.Args()
	if len(flags) < 1 {
		usage()
		return fmt.Errorf("must provide at least one filename for the record")
	}

	// Open all files and digest them.
	hashes := make([]*[sha256.Size]byte, 0, len(flags))
	for _, filename := range flags {
		var payload []byte
		payload, err := ioutil.ReadFile(filename)
		if err != nil {
			return err
		}

		// Digest
		h := sha256.New()
		h.Write(payload)
		digest := h.Sum(nil)

		var digest32 [sha256.Size]byte
		copy(digest32[:], digest)
		hashes = append(hashes, &digest32)
	}

	merkle := *merkle.Root(hashes)
	merkleToken := make([]byte, len(merkle)+len(token))
	copy(merkleToken, merkle[:])
	copy(merkleToken[len(merkle[:]):], token)
	if ed25519.Verify(&key, merkleToken, &signature) {
		fmt.Println("Record successfully verified")
	} else {
		if *verboseFlag {
			return fmt.Errorf("Record failed verification. Please ensure the "+
				"public key and merkle are correct.\n"+
				"  Merkle: %v", hex.EncodeToString(merkle[:]))
		}

		return fmt.Errorf("Record failed verification")
	}

	return nil
}

func _main() error {
	flag.Parse()
	if publicKeyFlag == nil && tokenFlag == nil && signatureFlag == nil {
		usage()
		return fmt.Errorf("must provide all listed parameters")
	}

	// Decode the public key, token and signature.
	k, err := hex.DecodeString(*publicKeyFlag)
	if err != nil {
		return err
	}
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], k)

	token, err := hex.DecodeString(*tokenFlag)
	if err != nil {
		return err
	}

	s, err := hex.DecodeString(*signatureFlag)
	if err != nil {
		return err
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], s)

	return verifyRecord(publicKey, token, signature)
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
