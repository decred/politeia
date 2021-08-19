// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	v1 "github.com/decred/dcrtime/api/v1"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/politeiad/sharedconfig"
	"github.com/decred/politeia/util"
)

// TODO: make configurable
var (
	defaultTlogHost = "localhost:8090"
	defaultTlogPass = "tlogpass"
	defaultDBType   = "mysql"
	defaultDBHost   = "localhost:3306"
	defaultDBPass   = "politeiadpass"
	defaultHomeDir  = sharedconfig.DefaultHomeDir
	defaultDataDir  = filepath.Join(defaultHomeDir, sharedconfig.DefaultDataDirname)
	activeNetParams = &params{
		Params:              chaincfg.TestNet3Params(),
		WalletRPCServerPort: "9111",
	}
)

type legacyImport struct {
	sync.RWMutex
	tstore *tstore.Tstore
	client *http.Client

	// comments is a cache used for feeding the parentID data to the
	// comment del metadata payload.
	comments map[string]map[string]decredplugin.Comment // [legacyToken][commentid]comment
}

func newLegacyImport() (*legacyImport, error) {
	// Initialize tstore instance.
	ts, err := tstore.New(defaultHomeDir, defaultDataDir, activeNetParams.Params,
		defaultTlogHost, defaultTlogPass, defaultDBType, defaultDBHost, defaultDBPass, v1.DefaultTestnetTimeHost,
		"")
	if err != nil {
		return nil, err
	}

	// Initialize http client to make pi requests.
	c, err := util.NewHTTPClient(false, "")
	if err != nil {
		return nil, err
	}

	return &legacyImport{
		tstore:   ts,
		client:   c,
		comments: make(map[string]map[string]decredplugin.Comment),
	}, nil
}

func _main() error {
	flag.Parse()
	if len(flag.Args()) == 0 {
		return fmt.Errorf("need path for cloned git repo repository")
	}

	path := util.CleanAndExpandPath(flag.Arg(0))
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	l, err := newLegacyImport()
	if err != nil {
		return err
	}

	// Parse data
	var (
		files      []backend.File
		metadata   []backend.MetadataStream
		proposalmd pi.ProposalMetadata
		recordmd   *backend.RecordMetadata

		// test vars will refactor
		commentsPath string
		ballotPath   string

		// This metadata stream needs to be edited further along the parsing
		// process as to change its token to the new tlog token.
		authdetailsmd *ticketvote.AuthDetails
		startvotemd   *ticketvote.Start
		votedetailsmd *ticketvote.VoteDetails
	)
	err = filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Start of a new record version folder. This tool will parse
			// the last version of each legacy record and treat it as version 1
			// tlog backend.

			// Build user metadata and get proposal name.
			if info.Name() == "00.metadata.txt" {
				usermd, n, err := l.convertProposalGeneral(path)
				if err != nil {
					return err
				}
				proposalmd.Name = n
				b, err := json.Marshal(usermd)
				if err != nil {
					return err
				}
				metadata = append(metadata, backend.MetadataStream{
					PluginID: pusermd.PluginID,
					StreamID: pusermd.StreamIDUserMetadata,
					Payload:  string(b),
				})
			}

			// Build status change metadata.
			if info.Name() == "02.metadata.txt" {
				statuschangemd, err := convertStatusChangeMetadata(path)
				if err != nil {
					return err
				}
				b, err := json.Marshal(statuschangemd)
				if err != nil {
					return err
				}
				metadata = append(metadata, backend.MetadataStream{
					PluginID: pusermd.PluginID,
					StreamID: pusermd.StreamIDStatusChanges,
					Payload:  string(b),
				})
			}

			// Build authorize vote metadata.
			if info.Name() == "13.metadata.txt" {
				authdetailsmd, err = convertAuthDetailsMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build start vote metadata.
			if info.Name() == "14.metadata.txt" {
				startvotemd, err = convertStartVoteMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build vote details metadata.
			if info.Name() == "15.metadata.txt" {
				votedetailsmd, err = convertVoteDetailsMetadata(path, startvotemd.Starts)
				if err != nil {
					return err
				}
			}

			// Build indexmd file.
			if info.Name() == "index.md" {
				indexmd := &backend.File{
					Name: info.Name(),
				}
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				indexmd.Payload = base64.StdEncoding.EncodeToString(b)
				indexmd.MIME = mime.DetectMimeType(b)
				indexmd.Digest = hex.EncodeToString(util.Digest(b))

				files = append(files, *indexmd)
			}
			if info.Name() == "proposalmetadata.json" {
				// record is version 2 metadatas, parse name
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				type proposalMetadata struct {
					Name   string
					LinkTo string // Token of proposal to link to
					LinkBy int64  // UNIX timestamp of RFP deadline
				}
				var pm proposalMetadata
				err = json.Unmarshal(b, &pm)
				if err != nil {
					return err
				}

				proposalmd.Name = pm.Name
			}

			// Navigate comments journal and call plugin writes for each
			// comment action.
			if info.Name() == "comments.journal" {
				commentsPath = path
			}

			// Navigate vote journal
			if info.Name() == "ballot.journal" {
				ballotPath = path
			}

			if info.Name() == "recordmetadata.json" {
				recordmd, err = convertRecordMetadata(path)
				if err != nil {
					return err
				}
				// Store legacy token for future use.
				proposalmd.LegacyToken = recordmd.Token
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	// Setup proposal metadata payload and file.
	//
	// The files slice will contain:
	//   - index.md
	//   - proposalmetadata.json
	//   - votemetadata.json (for rfp props)
	b, err := json.Marshal(proposalmd)
	if err != nil {
		return err
	}
	pmd := &backend.File{
		Name:    "proposalmetadata.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
	}
	files = append(files, *pmd)

	// Save legacy record on tstore.
	newToken, err := l.recordSave(files, metadata, *recordmd)
	if err != nil {
		return err
	}

	// Save authorize vote blob, if any
	if !reflect.DeepEqual(*authdetailsmd, ticketvote.AuthDetails{}) {
		err = l.blobSaveAuthDetails(*authdetailsmd, newToken)
		if err != nil {
			return err
		}
	}

	// Save vote details blob, if any
	if !reflect.DeepEqual(*votedetailsmd, ticketvote.VoteDetails{}) {
		err = l.blobSaveVoteDetails(*votedetailsmd, newToken)
		if err != nil {
			return err
		}
	}

	// Navigate and convert comments journal.
	err = l.convertCommentsJournal(commentsPath, newToken)
	if err != nil {
		return err
	}

	// Navigate and convert vote ballot journal.
	err = l.convertBallotJournal(ballotPath, newToken)
	if err != nil {
		return err
	}

	fmt.Println("new token")
	fmt.Println(hex.EncodeToString(newToken))
	fmt.Println("legacy token")
	fmt.Println(proposalmd.LegacyToken)
	fmt.Println("name")
	fmt.Println(proposalmd.Name)

	fmt.Println("Done!")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
