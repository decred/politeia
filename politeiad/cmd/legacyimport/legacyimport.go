// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/decredplugin"
	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
)

const (
	defaultTlogHost = "localhost:8090"
	defaultTlogPass = "tlogpass"
	defaultDBType   = "mysql"
	defaultDBHost   = "localhost:3306"
	defaultDBPass   = "politeiadpass"

	defaultDataDirname = "data"
)

var (
	defaultHomeDir  = dcrutil.AppDataDir("politeiad", false)
	defaultDataDir  = filepath.Join(defaultHomeDir, defaultDataDirname)
	activeNetParams = &params{
		Params:              chaincfg.TestNet3Params(),
		WalletRPCServerPort: "9111",
	}

	// Configurable flags
	gitpath   = flag.String("gitpath", "", "path to git record repository")
	tlogHost  = flag.String("tloghost", defaultTlogHost, "tlog host")
	tlogPass  = flag.String("tlogpass", defaultTlogPass, "tlog pass")
	dbHost    = flag.String("dbhost", defaultDBHost, "mysql DB host")
	dbPass    = flag.String("dbpass", defaultDBPass, "mysql DB pass")
	commentsf = flag.Bool("comments", false, "parse comments journal")
	ballot    = flag.Bool("ballot", false, "parse ballot journal")

	errorIsRFPSubmission = errors.New("is rfp submission")
)

type legacyImport struct {
	sync.RWMutex
	tstore *tstore.Tstore
	client *http.Client

	// comments is a cache used for feeding the parentID data to the
	// comment del metadata payload.
	comments map[string]map[string]decredplugin.Comment // [legacyToken][commentid]comment

	// tokens is a cache that maps legacy tokens to new tlog tokens, and
	// is used to get the new token from a legacy RFP proposal for their
	// submissions and feed the LinkTo metadata field.
	tokens map[string]string // [legacyToken]newToken

	// queue holds the RFP submission record paths that needs to be parsed
	// last, when their respective RFP parent has already been inserted.
	queue []string

	rfpParents map[string]*startRunoffRecord
}

func newLegacyImport() (*legacyImport, error) {
	// Initialize tstore instance.
	ts, err := tstore.New(defaultHomeDir, defaultDataDir, activeNetParams.Params,
		*tlogHost, *tlogPass, defaultDBType, *dbHost, *dbPass,
		v1.DefaultTestnetTimeHost,
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
		tstore:     ts,
		client:     c,
		comments:   make(map[string]map[string]decredplugin.Comment),
		tokens:     make(map[string]string),
		rfpParents: make(map[string]*startRunoffRecord),
	}, nil
}

// preParsePaths builds an optimized traversal path for the git record
// repository.
func preParsePaths(path string) (map[string]string, error) {
	// Pre-parse git records folder and get the path for each record's
	// latest version.
	var (
		token       string
		version     int
		versionPath string

		paths map[string]string = make(map[string]string) // [legacyToken]path
	)
	err := filepath.Walk(path,
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

			paths[token] = versionPath

			return nil
		})
	if err != nil {
		return nil, err
	}

	return paths, nil
}

// parseRecordData will navigate the legacy record path and parse all necessary
// data for tlog.
func (l *legacyImport) parseRecordData(rootpath string) (*parsedData, error) {
	var (
		files          []backend.File
		metadata       []backend.MetadataStream
		proposalMd     pi.ProposalMetadata
		voteMd         ticketvote.VoteMetadata
		recordMd       *backend.RecordMetadata
		statusChangeMd *usermd.StatusChangeMetadata
		startVoteMd    *ticketvote.Start
		authDetailsMd  *ticketvote.AuthDetails
		voteDetailsMd  *ticketvote.VoteDetails
		commentsPath   string
		ballotPath     string
		parentToken    string
	)
	err := filepath.Walk(rootpath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Build user metadata and get proposal name.
			if info.Name() == "00.metadata.txt" {
				usermd, name, err := l.convertUserMetadata(path)
				if err != nil {
					return err
				}
				proposalMd.Name = name
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
				statusChangeMd, err = convertStatusChangeMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build authorize vote metadata.
			if info.Name() == "13.metadata.txt" {
				authDetailsMd, err = convertAuthDetailsMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build start vote metadata.
			if info.Name() == "14.metadata.txt" {
				startVoteMd, err = convertStartVoteMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build vote details metadata.
			if info.Name() == "15.metadata.txt" {
				voteDetailsMd, err = convertVoteDetailsMetadata(path, startVoteMd.Starts)
				if err != nil {
					return err
				}
			}

			// Build indexmd file.
			if info.Name() == "index.md" {
				indexMd := &backend.File{
					Name: info.Name(),
				}
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				indexMd.Payload = base64.StdEncoding.EncodeToString(b)
				indexMd.MIME = mime.DetectMimeType(b)
				indexMd.Digest = hex.EncodeToString(util.Digest(b))

				files = append(files, *indexMd)
			}

			// Build proposal metadata, and vote metadata if needed.
			if info.Name() == "proposalmetadata.json" {
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}
				var pm proposalMetadata
				err = json.Unmarshal(b, &pm)
				if err != nil {
					return err
				}

				// Parse vote metadata.
				if pm.LinkTo != "" {
					l.RLock()
					linkTo := l.tokens[pm.LinkTo]
					l.RUnlock()

					if linkTo == "" {
						// RFP Parent has not been inserted yet, put this record
						// on queue.
						l.Lock()
						l.queue = append(l.queue, rootpath)
						l.Unlock()
						return errorIsRFPSubmission
					}

					// Link to RFP parent's new tlog token.
					voteMd.LinkTo = linkTo
					parentToken = linkTo
				}
				if pm.LinkBy != 0 {
					voteMd.LinkBy = pm.LinkBy
				}
				proposalMd.Name = pm.Name
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
				recordMd, err = convertRecordMetadata(path)
				if err != nil {
					return err
				}
				// Store legacy token.
				proposalMd.LegacyToken = recordMd.Token
			}

			return nil
		})
	if err != nil {
		return nil, err
	}

	// Setup proposal metadata file.
	b, err := json.Marshal(proposalMd)
	if err != nil {
		return nil, err
	}
	pmd := &backend.File{
		Name:    "proposalmetadata.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
	}
	files = append(files, *pmd)

	// Setup vote metadata file if needed.
	if voteMd.LinkBy != 0 || voteMd.LinkTo != "" {
		b, err := json.Marshal(voteMd)
		if err != nil {
			return nil, err
		}
		vmd := &backend.File{
			Name:    "votemetadata.json",
			MIME:    mime.DetectMimeType(b),
			Digest:  hex.EncodeToString(util.Digest(b)),
			Payload: base64.StdEncoding.EncodeToString(b),
		}
		files = append(files, *vmd)
	}

	// Check if record is a RFP Parent. If so, save to cache for future
	// reference.
	if voteMd.LinkBy != 0 {
		l.Lock()
		l.rfpParents[proposalMd.LegacyToken] = &startRunoffRecord{
			// Submissions:   Will be set when all records have been parsed and inserted.
			Mask:             voteDetailsMd.Params.Mask,
			Duration:         voteDetailsMd.Params.Duration,
			QuorumPercentage: voteDetailsMd.Params.QuorumPercentage,
			PassPercentage:   voteDetailsMd.Params.PassPercentage,
			StartBlockHeight: voteDetailsMd.StartBlockHeight,
			StartBlockHash:   voteDetailsMd.StartBlockHash,
			EndBlockHeight:   voteDetailsMd.EndBlockHeight,
			EligibleTickets:  voteDetailsMd.EligibleTickets,
		}
		l.Unlock()
	}

	// Set parent token on vote details metadata, if needed
	if parentToken != "" {
		voteDetailsMd.Params.Parent = parentToken
	}

	// This marks the end of the parsing process for the specified git
	// record path, and returns all data needed by tstore on the parsedData
	// struct.
	return &parsedData{
		files:          files,
		metadata:       metadata,
		recordMd:       recordMd,
		statusChangeMd: statusChangeMd,
		authDetailsMd:  authDetailsMd,
		voteDetailsMd:  voteDetailsMd,
		commentsPath:   commentsPath,
		ballotPath:     ballotPath,
		legacyToken:    proposalMd.LegacyToken,
		parentToken:    parentToken,
	}, nil
}

// saveRecordData saves the parsed data onto tstore.
func (l *legacyImport) saveRecordData(data parsedData) ([]byte, error) {
	// Create a new tlog tree for the legacy record.
	newToken, err := l.tstore.RecordNew()
	if err != nil {
		return nil, err
	}

	// Save new token to record metadata.
	data.recordMd.Token = hex.EncodeToString(newToken)
	// Save new token to status change metadata.
	data.statusChangeMd.Token = hex.EncodeToString(newToken)

	// Check to see if record is RFP. If so, update the RFP parents cache with
	// the new tlog token.
	l.Lock()
	_, ok := l.rfpParents[data.legacyToken]
	if ok {
		l.rfpParents[hex.EncodeToString(newToken)] = l.rfpParents[data.legacyToken]
		delete(l.rfpParents, data.legacyToken)
	}
	l.Unlock()

	// Check if record in question is an RFP submission. If so, add it to the
	// submissions list of its parent.
	if data.parentToken != "" {
		l.Lock()
		l.rfpParents[data.parentToken].Submissions = append(
			l.rfpParents[data.parentToken].Submissions, data.recordMd.Token)
		l.Unlock()
	}

	// Add status change metadata to metadata stream.
	b, err := json.Marshal(data.statusChangeMd)
	if err != nil {
		return nil, err
	}
	data.metadata = append(data.metadata, backend.MetadataStream{
		PluginID: pusermd.PluginID,
		StreamID: pusermd.StreamIDStatusChanges,
		Payload:  string(b),
	})

	// Save record to tstore.
	err = l.recordSave(newToken, data.files, data.metadata, *data.recordMd)
	if err != nil {
		return nil, err
	}

	// Save authorize vote blob, if any.
	if data.authDetailsMd != nil {
		err = l.blobSaveAuthDetails(*data.authDetailsMd, newToken)
		if err != nil {
			return nil, err
		}
	}

	// Save vote details blob, if any.
	if data.voteDetailsMd != nil {
		if data.parentToken != "" {
			data.voteDetailsMd.Params.Parent = data.parentToken
		}
		err = l.blobSaveVoteDetails(*data.voteDetailsMd, newToken)
		if err != nil {
			return nil, err
		}
	}

	// TODO: Concurrently parse comments and votes for each record.
	// wait group for both routines.

	var wg sync.WaitGroup
	// Spin routine for parsing comments.
	wg.Add(1)
	go func() error {
		defer wg.Done()
		// Navigate and convert comments journal.
		if data.commentsPath != "" && *commentsf {
			err = l.convertCommentsJournal(data.commentsPath, data.legacyToken, newToken)
			if err != nil {
				return err
			}
		}
		return nil
	}()
	// Spin routine for parsing votes.
	wg.Add(1)
	go func() error {
		defer wg.Done()
		// Navigate and convert vote ballot journal.
		if data.ballotPath != "" && *ballot {
			err = l.convertBallotJournal(data.ballotPath, data.legacyToken, newToken)
			if err != nil {
				return err
			}
		}
		return nil
	}()

	wg.Wait()

	fmt.Println("DONE PARSING COMMENTS&VOTES CONCURRENTLY")

	// Save legacy token to new token mapping in cache.
	l.Lock()
	l.tokens[data.legacyToken] = hex.EncodeToString(newToken)
	l.Unlock()

	return newToken, nil
}

func _main() error {
	fmt.Println("legacyimport: Start!")

	flag.Parse()
	if *gitpath == "" {
		return fmt.Errorf("missing path for cloned git record repository")
	}

	path := util.CleanAndExpandPath(*gitpath)
	_, err := os.Stat(path)
	if err != nil {
		return err
	}

	fmt.Println("legacyimport: Opening connection with tstore")

	l, err := newLegacyImport()
	if err != nil {
		return err
	}

	fmt.Println("legacyimport: Pre parsing record paths...")

	paths, err := preParsePaths(path)
	if err != nil {
		return err
	}

	fmt.Printf("legacyimport: Pre parsing complete, parsing %v records...\n", len(paths))

	// First we parse and add all records that are not RFP submissions to
	// tstore. This is done because their respective RFP parent needs to be
	// added first in order to link to the new tlog token correctly.
	i := 0
	var wg sync.WaitGroup
	for _, path := range paths {
		pData, err := l.parseRecordData(path)
		if err == errorIsRFPSubmission {
			// This record is an RFP submission and is on queue, will be parsed
			// last.
			continue
		}
		if err != nil {
			return err
		}

		fmt.Printf("legacyimport: Parsing record %v on thread %v\n",
			pData.recordMd.Token, i)

		i++
		wg.Add(1)
		go func(data parsedData) error {
			defer wg.Done()

			// Save legacy record on tstore.
			newToken, err := l.saveRecordData(data)
			if err != nil {
				panic(err)
			}

			fmt.Printf("legacyimport: Parsed record %v. new tlog token: %v\n",
				data.legacyToken, hex.EncodeToString(newToken))

			return nil
		}(*pData)
	}
	wg.Wait()

	fmt.Println("legacyimport: Done parsing first batch!")

	fmt.Printf("legacyimport: Parsing %v on queue records...\n", len(l.queue))

	// Now we parse the remaining RFP submission proposals.
	i = 0
	var qwg sync.WaitGroup
	for _, path = range l.queue {
		pData, err := l.parseRecordData(path)
		if err != nil {
			return err
		}

		fmt.Printf("legacyimport: Parsing queued record %v on thread %v\n",
			pData.recordMd.Token, i)

		i++
		qwg.Add(1)
		go func(data parsedData) error {
			defer qwg.Done()

			// Save legacy record on tstore.
			newToken, err := l.saveRecordData(data)
			if err != nil {
				return err
			}

			fmt.Printf("legacyimport: Parsed record %v. new tlog token: %v\n",
				data.legacyToken, hex.EncodeToString(newToken))

			return nil
		}(*pData)
	}

	qwg.Wait()

	// Now we add the dataDescriptorStartRunoff blob for each RFP parent while
	// building the submissions list.
	l.RLock()
	for token, startRunoffRecord := range l.rfpParents {
		b, err := hex.DecodeString(token)
		if err != nil {
			return err
		}
		err = l.blobSaveStartRunoff(*startRunoffRecord, b)
		if err != nil {
			return err
		}
	}
	l.RUnlock()

	fmt.Println("legacyimport: Done!")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
