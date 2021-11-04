package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/decred/politeia/decredplugin"
	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	tv "github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
)

// cmdDump receives the git repository path for the legacy records and dumps
// .
func (l *legacy) cmdDump(gitPath string) error {

	paths, err := l.parsePaths(gitPath)
	if err != nil {
		return err
	}

	// IMPORTANT !!
	// Parse vote timestamps before dumping data
	// ts, err := parseVoteTimestamps(path)
	// if err != nil {
	// 	return err
	// }
	// l.Lock()
	// l.timestamps = ts
	// l.Unlock()
	if !*cmdDumpTest {
		timestamps, err := parseVoteTimestamps(gitPath)
		if err != nil {
			return err
		}
		l.Lock()
		l.timestamps = timestamps
		l.Unlock()
	}

	var (
		i    = 1
		wg   sync.WaitGroup
		dump = make(map[string]parsedData, len(paths))
	)
	for legacyToken, path := range paths {

		fmt.Printf("legacy: %v record being parsed on thread %v\n", legacyToken[:7], i)

		wg.Add(1)
		i++

		go func(token, p string) error {
			defer wg.Done()

			// Parse repository data.
			parsedData, err := l.parseRecordData(p)
			if err != nil {
				panic(err)
			}

			// Parse ballot journal with external dcrdata data.
			if parsedData.BallotPath != "" {
				tickets := parsedData.VoteDetailsMd.EligibleTickets
				votes, err := l.parseBallotJournal(parsedData.BallotPath, token, gitPath,
					tickets)
				if err != nil {
					panic(err)
				}
				parsedData.Votes = votes
			}

			// Parse comment journal with external pi data.
			if parsedData.CommentsPath != "" {
				comments, err := l.parseCommentsJournal(parsedData.CommentsPath, token)
				if err != nil {
					panic(err)
				}
				parsedData.Comments = comments
			}

			l.Lock()
			dump[token] = *parsedData
			l.Unlock()

			fmt.Printf("legacy: %v done!\n", token[:7])

			return nil
		}(legacyToken, path)
	}

	wg.Wait()

	fmt.Println("legacy: Writing json file dump")

	pwd, err := os.Getwd()
	if err != nil {
		return err
	}

	var dataPath string
	if *cmdDumpOut == "" {
		dataPath = filepath.Join(pwd, "data")
	} else {
		dataPath = filepath.Join(*cmdDumpOut, "data")
	}

	for legacyToken, data := range dump {
		err := os.MkdirAll(dataPath, os.ModePerm)
		if err != nil {
			return err
		}
		f, err := os.Create(dataPath + "/" + legacyToken[:7] + ".json")
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if err != nil {
			return err
		}
	}

	return nil
}

// parsePaths builds an optimized traversal path for the git record
// repository.
func (l *legacy) parsePaths(path string) (map[string]string, error) {
	// Walk the repository and parse the location of each record's latest
	// version.
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

			// Save version path on the paths slice to be returned.
			paths[token] = versionPath

			// Save cache of legacy record latest version.
			l.Lock()
			l.versions[token] = version
			l.Unlock()

			return nil
		})
	if err != nil {
		return nil, err
	}

	return paths, nil
}

// parseRecordData walks through the legacy record path and parses all necessary
// data for tstore.
func (l *legacy) parseRecordData(recordpath string) (*parsedData, error) {
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
	err := filepath.Walk(recordpath,
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
				// Get correct record version from cache. The version in 13.metadata.txt
				// is not coherent. This makes the signature verify successfully.
				l.RLock()
				authDetailsMd.Version = uint32(l.versions[authDetailsMd.Token])
				l.RUnlock()
			}

			// Build start vote metadata.
			if info.Name() == "14.metadata.txt" {
				startVoteMd, err = l.convertStartVoteMetadata(path)
				if err != nil {
					return err
				}
			}

			// Build vote details metadata.
			if info.Name() == "15.metadata.txt" {
				voteDetailsMd, err = convertVoteDetailsMetadata(path, startVoteMd.Starts[0])
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
					voteMd.LinkTo = pm.LinkTo
					parentToken = pm.LinkTo // TODO: revisit. not needed
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

	// Check if record is a RFP Parent. If so, save the start runoff blob
	// to be saved later on.
	if voteMd.LinkBy != 0 {
		l.Lock()
		l.rfpParents[proposalMd.LegacyToken] = &startRunoffRecord{
			// Submissions:   Will be set when all records have been parsed
			// 				  and inserted to tstore.
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

	// Set parent token on vote details metadata, if needed.
	if parentToken != "" {
		voteDetailsMd.Params.Parent = parentToken
	}

	// This marks the end of the parsing process for the specified git
	// record path, and returns all data needed by tstore on the parsedData
	// struct.
	return &parsedData{
		Files:          files,
		Metadata:       metadata,
		RecordMd:       recordMd,
		StatusChangeMd: statusChangeMd,
		AuthDetailsMd:  authDetailsMd,
		VoteDetailsMd:  voteDetailsMd,
		CommentsPath:   commentsPath,
		BallotPath:     ballotPath,
		LegacyToken:    proposalMd.LegacyToken,
		ParentToken:    parentToken,
	}, nil
}

// parseBallotJournal walks through the ballot journal and converts the payloads
// to their tstore blob equivalents.
func (l *legacy) parseBallotJournal(path, legacyToken, gitPath string, tickets []string) ([]*tv.CastVoteDetails, error) {
	if path == "" {
		return nil, nil
	}

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return nil, err
	}

	addrs, err := fetchLargestCommitmentAddrs(tickets)
	if err != nil {
		return nil, err
	}

	var (
		castVoteDetails []*tv.CastVoteDetails
	)
	s := bufio.NewScanner(fh)
	for i := 0; s.Scan(); i++ {
		ss := bytes.NewReader([]byte(s.Text()))
		d := json.NewDecoder(ss)
		var action gitbe.JournalAction
		err := d.Decode(&action)
		if err != nil {
			return nil, err
		}

		switch action.Action {
		case "add":
			var cvj castVoteJournalV1
			err = d.Decode(&cvj)
			if err != nil {
				return nil, err
			}

			cvd := &tv.CastVoteDetails{
				Token:     cvj.CastVote.Token,
				Ticket:    cvj.CastVote.Ticket,
				VoteBit:   cvj.CastVote.VoteBit,
				Signature: cvj.CastVote.Signature,
				Address:   addrs[cvj.CastVote.Ticket],
				Receipt:   cvj.Receipt,
				// Timestamp: timestamps[legacyToken][cvj.CastVote.Ticket],
			}

			if !*cmdDumpTest {
				l.RLock()
				cvd.Timestamp = l.timestamps[legacyToken][cvj.CastVote.Ticket]
				l.RUnlock()
			}

			castVoteDetails = append(castVoteDetails, cvd)

		default:
			return nil, fmt.Errorf("invalid ballot journal action")
		}

		if *cmdDumpTest {
			if len(castVoteDetails) == cmdDumpBallotCount {
				break
			}
		}
	}

	return castVoteDetails, nil
}

// parseCommentsJournal walks through the comments journal and converts the
// payloads to their tstore blob equivalents.
func (l *legacy) parseCommentsJournal(path, legacyToken string) (*parsedComments, error) {
	if path == "" {
		return nil, nil
	}

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return nil, err
	}

	var (
		parentIDs = make(map[string]string)

		adds  []comments.CommentAdd
		dels  []comments.CommentDel
		votes []comments.CommentVote
	)

	s := bufio.NewScanner(fh)
	for i := 0; s.Scan(); i++ {
		ss := bytes.NewReader([]byte(s.Text()))
		d := json.NewDecoder(ss)

		var action gitbe.JournalAction
		err := d.Decode(&action)
		if err != nil {
			return nil, err
		}

		switch action.Action {
		case "add":
			var c decredplugin.Comment
			err = d.Decode(&c)
			if err != nil {
				return nil, err
			}

			// Get user id from pubkey.
			usr, err := l.fetchUserByPubKey(c.PublicKey)
			if err != nil {
				return nil, err
			}

			// Check if test mode is set and adjust.
			userID := usr.ID
			if *cmdDumpTest {
				userID = cmdDumpUserID
			}

			// Parse IDs.
			pid, err := strconv.Atoi(c.ParentID)
			if err != nil {
				return nil, err
			}
			cid, err := strconv.Atoi(c.CommentID)
			if err != nil {
				return nil, err
			}

			// Append add blob.
			adds = append(adds, comments.CommentAdd{
				UserID:    userID,
				State:     comments.RecordStateVetted,
				Token:     c.Token,
				ParentID:  uint32(pid),
				Comment:   c.Comment,
				PublicKey: c.PublicKey,
				Signature: c.Signature,
				CommentID: uint32(cid),
				Version:   1,
				Timestamp: c.Timestamp,
				Receipt:   c.Receipt,
			})

			parentIDs[c.CommentID] = c.ParentID
		case "del":
			var cc decredplugin.CensorComment
			err = d.Decode(&cc)
			if err != nil {
				return nil, err
			}

			// Get user ID from pubkey.
			usr, err := l.fetchUserByPubKey(cc.PublicKey)
			if err != nil {
				return nil, err
			}

			// Check if test mode is set and adjust.
			userID := usr.ID
			if *cmdDumpTest {
				userID = cmdDumpUserID
			}

			// Parse IDs.
			parentID := parentIDs[cc.CommentID]
			pid, err := strconv.Atoi(parentID)
			if err != nil {
				return nil, err
			}
			cid, err := strconv.Atoi(cc.CommentID)
			if err != nil {
				return nil, err
			}

			// Append del blob.
			dels = append(dels, comments.CommentDel{
				Token:     cc.Token,
				State:     comments.RecordStateVetted,
				CommentID: uint32(cid),
				Reason:    cc.Reason,
				PublicKey: cc.PublicKey,
				Signature: cc.Signature,

				ParentID:  uint32(pid),
				UserID:    userID,
				Timestamp: cc.Timestamp,
				Receipt:   cc.Receipt,
			})
		case "addlike":
			var lc likeCommentV1
			err = d.Decode(&lc)
			if err != nil {
				return nil, err
			}

			// Get user ID from pubkey.
			usr, err := l.fetchUserByPubKey(lc.PublicKey)
			if err != nil {
				return nil, err
			}

			// Check if test mode is set and adjust.
			userID := usr.ID
			if *cmdDumpTest {
				userID = cmdDumpUserID
			}

			// Parse comment ID.
			cid, err := strconv.Atoi(lc.CommentID)
			if err != nil {
				return nil, err
			}

			// Parse comment vote.
			var vote comments.VoteT
			switch {
			case lc.Action == "1":
				vote = comments.VoteUpvote
			case lc.Action == "-1":
				vote = comments.VoteDownvote
			default:
				return nil, fmt.Errorf("invalid comment vote code")
			}

			// Append vote blob.
			votes = append(votes, comments.CommentVote{
				UserID:    userID,
				State:     comments.RecordStateVetted,
				Token:     lc.Token,
				CommentID: uint32(cid),
				Vote:      vote,
				PublicKey: lc.PublicKey,
				Signature: lc.Signature,
				Timestamp: lc.Timestamp,
				Receipt:   lc.Receipt,
			})
		default:
			return nil, err
		}
	}

	return &parsedComments{
		Adds:  adds,
		Dels:  dels,
		Votes: votes,
	}, nil
}
