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
	"strconv"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/decredplugin"
	pdv1 "github.com/decred/politeia/politeiad/api/v1"
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

	// flags
	flagTlogHost = flag.String("tloghost", defaultTlogHost, "tlog host")
	flagTlogPass = flag.String("tlogpass", defaultTlogPass, "tlog pass")
	flagDBHost   = flag.String("dbhost", defaultTlogHost, "mysql DB host")
	flagDBPass   = flag.String("dbpass", defaultTlogHost, "mysql DB pass")
)

type legacyImport struct {
	sync.RWMutex
	tstore *tstore.Tstore
	client *http.Client

	// comments is a cache used for feeding the parentID data to the
	// comment del metadata payload.
	comments map[string]map[string]decredplugin.Comment // [legacyToken][commentid]comment

	// tokens is a cache that maps legacy tokens to new tlog tokens.
	tokens map[string]string // [legacyToken]newToken
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
		tokens:   make(map[string]string),
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

	fmt.Println("legacyimport: Pre parsing record paths...")

	// Pre-parse git records folder. This is done to build a optimal path
	// traversal order. In this step we store the record's latest version path.
	type parsedPath struct {
		path            string
		isRFPSubmission bool
	}
	var (
		token       string
		version     int
		versionPath string

		paths map[string]parsedPath = make(map[string]parsedPath) // [legacyToken]path
	)
	err = filepath.Walk(path,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Reset helper vars.
			version = 0
			versionPath = ""

			if len(info.Name()) == pdv1.TokenSize*2 {
				// Start of a new record folder.
				token = info.Name()
			}

			isRFPSubmission := false
			if info.Name() == "proposalmetadata.json" {
				// Check if record in question is RFP submission.
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				type proposalMetadata struct {
					LinkTo string
				}
				var pm proposalMetadata
				err = json.Unmarshal(b, &pm)
				if err != nil {
					return err
				}
				if pm.LinkTo != "" {
					isRFPSubmission = true
				}
			}

			// Try to parse version folder name.
			v, err := strconv.Atoi(info.Name())
			if err != nil {
				// Not version folder, skip remaining of execution.
				return nil
			}

			if v > version {
				version = v
				versionPath = path
			}

			paths[token] = parsedPath{
				path:            versionPath,
				isRFPSubmission: isRFPSubmission,
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	// Sort the tokens in the optimal order to parse. This is done
	// to first parse RFP proposals and later on, the RFP submissions,
	// so that we can link to the correct proposal token.
	var sorted []string
	for _, p := range paths {
		if p.isRFPSubmission {
			sorted = append(sorted, p.path)
		} else {
			sorted = append([]string{p.path}, sorted...)
		}
	}

	fmt.Println("legacyimport: Pre parsing complete, parsing records...")

	var wg sync.WaitGroup
	for i, path := range sorted {
		// Parse data.
		var (
			files      []backend.File
			metadata   []backend.MetadataStream
			proposalmd pi.ProposalMetadata
			votemd     *ticketvote.VoteMetadata
			recordmd   *backend.RecordMetadata

			commentsPath string
			ballotPath   string

			startvotemd   *ticketvote.Start
			authdetailsmd *ticketvote.AuthDetails
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
					usermd, name, err := l.convertProposalGeneral(path)
					if err != nil {
						return err
					}
					proposalmd.Name = name
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

				// Build proposal metadata, and vote metadata if needed.
				if info.Name() == "proposalmetadata.json" {
					b, err := ioutil.ReadFile(path)
					if err != nil {
						return err
					}
					type proposalMetadata struct {
						Name   string
						LinkTo string
						LinkBy int64
					}
					var pm proposalMetadata
					err = json.Unmarshal(b, &pm)
					if err != nil {
						return err
					}

					// Parse relevant data.
					votemd = &ticketvote.VoteMetadata{}
					if pm.LinkTo != "" {
						l.RLock()
						votemd.LinkTo = l.tokens[pm.LinkTo]
						l.RUnlock()
					}
					if pm.LinkBy != 0 {
						votemd.LinkBy = pm.LinkBy
					}
					proposalmd.Name = pm.Name
				}

				// Save comments and ballot journal path for parsing later when
				// the record has been created.
				if info.Name() == "comments.journal" {
					commentsPath = path
				}
				if info.Name() == "ballot.journal" {
					ballotPath = path
				}

				// Parse record metadata.
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
			return fmt.Errorf("walk import dir: %v for path %v", err, path)
		}

		// Setup proposal metadata file.
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

		// Setup vote metadata file if needed.
		if votemd != nil {
			b, err := json.Marshal(votemd)
			if err != nil {
				return err
			}
			vmd := &backend.File{
				Name:    "votemetadata.json",
				MIME:    mime.DetectMimeType(b),
				Digest:  hex.EncodeToString(util.Digest(b)),
				Payload: base64.StdEncoding.EncodeToString(b),
			}
			files = append(files, *vmd)
		}

		// parsedData holds the record data needed by tlog after parsing
		// their entire respective git repository folder.
		type parsedData struct {
			files         []backend.File
			metadata      []backend.MetadataStream
			recordmd      *backend.RecordMetadata
			authdetailsmd *ticketvote.AuthDetails
			votedetailsmd *ticketvote.VoteDetails
			commentsPath  string
			ballotPath    string
		}
		pd := parsedData{
			files:         files,
			metadata:      metadata,
			recordmd:      recordmd,
			authdetailsmd: authdetailsmd,
			votedetailsmd: votedetailsmd,
			commentsPath:  commentsPath,
			ballotPath:    ballotPath,
		}

		fmt.Printf("legacyimport: Parsing record %v on thread %v\n", recordmd.Token, i)

		// Run record inserts on separate threads with the parsed
		// data.
		wg.Add(1) // add to wait group
		go func(data parsedData) error {
			defer wg.Done()

			// Save legacy record on tstore.
			newToken, err := l.recordSave(data.files, data.metadata, *data.recordmd)
			if err != nil {
				return err
			}

			// Save authorize vote blob, if any.
			if authdetailsmd != nil {
				err = l.blobSaveAuthDetails(*data.authdetailsmd, newToken)
				if err != nil {
					return err
				}
			}

			// Save vote details blob, if any.
			if votedetailsmd != nil {
				err = l.blobSaveVoteDetails(*data.votedetailsmd, newToken)
				if err != nil {
					return err
				}
			}

			// Navigate and convert comments journal.
			if commentsPath != "" {
				err = l.convertCommentsJournal(data.commentsPath, newToken)
				if err != nil {
					return err
				}
			}

			// Navigate and convert vote ballot journal.
			if ballotPath != "" {
				err = l.convertBallotJournal(data.ballotPath, newToken)
				if err != nil {
					return err
				}
			}

			// Save legacy token to new token mapping in cache.
			l.Lock()
			l.tokens[proposalmd.LegacyToken] = hex.EncodeToString(newToken)
			l.Unlock()

			fmt.Printf("legacyimport: Parsed record %v. new tlog token: %v\n",
				proposalmd.LegacyToken, hex.EncodeToString(newToken))

			return nil
		}(pd)

	}

	wg.Wait()

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
