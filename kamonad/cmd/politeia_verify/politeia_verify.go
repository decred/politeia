// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	jsonInFlag    = flag.String("jsonin", "", "JSON record file")
	jsonOutFlag   = flag.Bool("jsonout", false, "return output as JSON")
	verboseFlag   = flag.Bool("v", false, "verbose output")
)

type record struct {
	CensorshipRecord censorshipRecord `json:"censorshiprecord"`
	ServerPublicKey  string           `json:"serverPubkey"`
}

type censorshipRecord struct {
	Token     string `json:"token"`
	Merkle    string `json:"merkle"`
	Signature string `json:"signature"`
}

type output struct {
	Success bool `json:"success"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: politeia_verify [options]\n")
	fmt.Fprintf(os.Stderr, " options:\n")
	fmt.Fprintf(os.Stderr, "  -v                 - Verbose output\n")
	fmt.Fprintf(os.Stderr, "  -k <pubkey>        - Politiea's public server key\n")
	fmt.Fprintf(os.Stderr, "  -t <token>         - Record censorship token\n")
	fmt.Fprintf(os.Stderr, "  -s <signature>     - Record censorship "+
		"signature\n")
	fmt.Fprintf(os.Stderr, "  <filename...>      - One or more paths to the markdown "+
		"and image files that make up the record\n")
	fmt.Fprintf(os.Stderr, "  -jsonin <filename> - A path to a JSON file which "+
		"represents the record. If this option is set, the other input "+
		"options (-k, -t, -s) should not be provided.\n")
	fmt.Fprintf(os.Stderr, "  -jsonout           - JSON output\n")
	fmt.Fprintf(os.Stderr, "\n")
}

func findMerkle() (*[sha256.Size]byte, error) {
	flags := flag.Args()
	if len(flags) < 1 {
		usage()
		return nil, fmt.Errorf("must provide at least one filename for the record")
	}

	// Open all files and digest them.
	hashes := make([]*[sha256.Size]byte, 0, len(flags))
	for _, filename := range flags {
		var payload []byte
		payload, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		// Digest
		h := sha256.New()
		h.Write(payload)
		digest := h.Sum(nil)

		var digest32 [sha256.Size]byte
		copy(digest32[:], digest)
		hashes = append(hashes, &digest32)
	}

	return merkle.Root(hashes), nil
}

func verifyRecord(key [ed25519.PublicKeySize]byte, merkle, token string, signature [ed25519.SignatureSize]byte) bool {
	return ed25519.Verify(&key, []byte(merkle+token), &signature)
}

func _main() error {
	flag.Parse()
	if (*publicKeyFlag == "" || *tokenFlag == "" || *signatureFlag == "") &&
		*jsonInFlag == "" {
		usage()
		return fmt.Errorf("must provide enough input parameters")
	}
	if *publicKeyFlag != "" && *jsonInFlag != "" {
		usage()
		return fmt.Errorf("must only provide either -jsonin or the other " +
			"input parameters")
	}

	var keyStr, tokenStr, merkleStr, signatureStr string
	if *publicKeyFlag != "" {
		keyStr = *publicKeyFlag
		tokenStr = *tokenFlag
		signatureStr = *signatureFlag
	} else {
		var payload []byte
		payload, err := ioutil.ReadFile(*jsonInFlag)
		if err != nil {
			return err
		}

		var record record
		err = json.Unmarshal(payload, &record)
		if err != nil {
			return err
		}

		keyStr = record.ServerPublicKey
		tokenStr = record.CensorshipRecord.Token
		signatureStr = record.CensorshipRecord.Signature
		merkleStr = record.CensorshipRecord.Merkle
	}

	// Decode the public key, token and signature.
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return err
	}
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], key)

	sig, err := hex.DecodeString(signatureStr)
	if err != nil {
		return err
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], sig)

	var merkle [sha256.Size]byte
	if *publicKeyFlag != "" {
		merklePtr, err := findMerkle()
		if err != nil {
			return err
		}

		merkle = *merklePtr
	} else {
		bytes, err := hex.DecodeString(merkleStr)
		if err != nil {
			return err
		}

		copy(merkle[:], bytes)
	}

	recordVerified := verifyRecord(publicKey, hex.EncodeToString(merkle[:]),
		tokenStr, signature)
	if *jsonOutFlag {
		bytes, err := json.Marshal(output{
			Success: recordVerified,
		})
		if err != nil {
			return err
		}

		fmt.Println(string(bytes))
	} else {
		if recordVerified {
			fmt.Println("Record successfully verified")
		} else {
			if *verboseFlag {
				return fmt.Errorf("Record failed verification. Please ensure the "+
					"public key and merkle are correct.\n"+
					"  Merkle: %v", hex.EncodeToString(merkle[:]))
			}

			return fmt.Errorf("Record failed verification")
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
