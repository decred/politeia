// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/util"
)

func _main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("must provide a path for the cloned git repository" +
			"of the legacy proposals")
	}

	path := util.CleanAndExpandPath(flag.Arg(0))
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Data needed for tstore.RecordSave
	//  var token []byte
	//  var metadata []*backend.MetadataStream
	var files []*backend.File

	// First code to parse a single git record, then logic to navigate git repo
	err = filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Build files.
			if info.Name() == "index.md" {
				file, err := makeBackendFile(info.Name(), path)
				if err != nil {
					return err
				}
				files = append(files, file)
			}
			if info.Name() == "recordmetadata.json" {
				file, err := makeBackendFile(info.Name(), path)
				if err != nil {
					return err
				}
				files = append(files, file)
			}

			// Navigate comments journal.
			if info.Name() == "comments.journal" {
				fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
				if err != nil {
					return err
				}

				s := bufio.NewScanner(fh)

				for i := 0; s.Scan(); i++ {
					fmt.Printf("\n\n")
					fmt.Println(s.Text())
					fmt.Printf("\n\n")

					ss := bytes.NewReader([]byte(s.Text()))
					d := json.NewDecoder(ss)

					var action gitbe.JournalAction
					err := d.Decode(&action)
					if err != nil {
						return err
					}

					fmt.Println("action")
					fmt.Println(action)

					switch action.Action {

					case "add":
						var c decredplugin.Comment
						err = d.Decode(&c)
						if err != nil {
							return fmt.Errorf("journal add: %v",
								err)
						}

						fmt.Println("ADD ACTION, printing decoded comment")
						fmt.Println(c)

					case "del":
						var cc decredplugin.CensorComment
						err = d.Decode(&cc)
						if err != nil {
							return fmt.Errorf("journal censor: %v",
								err)
						}

						fmt.Println("DEL ACTION, printing decoded censor comment")

					case "addlike":
						type likeComment struct {
							Token     string `json:"token"`     // Censorship token
							CommentID string `json:"commentid"` // Comment ID
							Action    string `json:"action"`    // Up or downvote (1, -1)
							Signature string `json:"signature"` // Client Signature of Token+CommentID+Action
							PublicKey string `json:"publickey"` // Pubkey used for Signature

							Receipt   string `json:"receipt,omitempty"`   // Signature of Signature
							Timestamp int64  `json:"timestamp,omitempty"` // Received UNIX timestamp
						}
						var lc likeComment
						err = d.Decode(&lc)
						if err != nil {
							return fmt.Errorf("journal addlike: %v", err)
						}
						fmt.Println(lc)

					default:
						return fmt.Errorf("invalid action: %v",
							action.Action)
					}
				}

			}

			return nil
		})

	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	fmt.Printf("Done!\n")

	return nil
}

// makeBackendFile takes a file path from a git record and converts it to a
// backend v2 file. Intended to be used on index.md and recordmetadata.json.
func makeBackendFile(name, path string) (*backend.File, error) {
	file := &backend.File{
		Name: name,
	}
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file.Payload = base64.StdEncoding.EncodeToString(b)
	file.MIME = mime.DetectMimeType(b)
	file.Digest = hex.EncodeToString(util.Digest(b))
	return file, nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
