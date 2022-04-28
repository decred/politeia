// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

const (
	// defaultLegacyDir is the default directory that the converted legacy data
	// is saved to.
	defaultLegacyDir = "./legacy-politeia-data"
)

var (
	// CLI flags for the convert command. We print a custom usage message,
	// see usage.go, so the individual flag usage messages are left blank.
	convertFlags = flag.NewFlagSet(convertCmdName, flag.ContinueOnError)
	legacyDir    = convertFlags.String("legacydir", defaultLegacyDir, "")
	convertToken = convertFlags.String("token", "", "")
	overwrite    = convertFlags.Bool("overwrite", false, "")
)

// execConvertComd executes the convert command.
//
// The convert command parses a legacy git repo, converts the data into types
// supported by the tstore backend, then writes the converted JSON data to
// disk. This data can be imported into tstore using the 'import' command.
func execConvertCmd(args []string) error {
	// Verify the git repo exists
	if len(args) == 0 {
		return fmt.Errorf("missing git repo argument")
	}
	gitRepo := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(gitRepo); err != nil {
		return fmt.Errorf("git repo not found: %v", gitRepo)
	}

	// Parse the CLI flags
	err := convertFlags.Parse(args[1:])
	if err != nil {
		return err
	}

	// Clean the legacy directory path
	*legacyDir = util.CleanAndExpandPath(*legacyDir)

	// Setup the legacy directory
	err = os.MkdirAll(*legacyDir, filePermissions)
	if err != nil {
		return err
	}

	client, err := util.NewHTTPClient(false, "")
	if err != nil {
		return err
	}

	// Setup the cmd context
	c := convertCmd{
		client:    client,
		gitRepo:   gitRepo,
		legacyDir: *legacyDir,
		token:     *convertToken,
		overwrite: *overwrite,
		userIDs:   make(map[string]string, 1024),
	}

	// Convert the legacy proposals
	return c.convertLegacyProposals()
}

// convertCmd represents the convert CLI command.
type convertCmd struct {
	sync.Mutex
	client    *http.Client
	gitRepo   string
	legacyDir string
	token     string
	overwrite bool

	// userIDs is used to memoize user ID by public key lookups, which require
	// querying the politeia API.
	userIDs map[string]string // [pubkey]userID
}

// convertLegacyProposals converts the legacy git backend proposals to tstore
// backend proposals then the converted proposals to disk as JSON encoded
// files. These converted proposals can be imported into a tstore backend using
// the import command.
func (c *convertCmd) convertLegacyProposals() error {
	// Build an inventory of all legacy proposal tokens
	tokens, err := parseProposalTokens(c.gitRepo)
	if err != nil {
		return err
	}

	fmt.Printf("Found %v legacy git proposals\n", len(tokens))

	// Convert the data for each proposal into tstore supported
	// types then save the converted proposal to disk.
	for i, token := range tokens {
		switch {
		case c.token != "" && c.token != token:
			// The caller only wants to convert a single
			// proposal and this is not it. Skip it.
			continue

		case c.token != "" && c.token == token:
			// The caller only wants to convert a single
			// proposal and this is it. Convert it.
			fmt.Printf("Converting proposal %v\n", token)

		default:
			// All proposals are being converted
			fmt.Printf("Converting proposal %v (%v/%v)\n",
				token, i+1, len(tokens))
		}

		// Skip the conversion if the converted proposal
		// already exists on disk.
		exists, err := proposalExists(c.legacyDir, token)
		if err != nil {
			return err
		}
		if exists && !c.overwrite {
			fmt.Printf("Proposal has already been converted; skipping\n")
			continue
		}

		// Get the path to the most recent version of the
		// proposal. We only import the most recent version.
		//
		// Example path: [gitRepo]/[token]/[version]/
		v, err := parseLatestProposalVersion(c.gitRepo, token)
		if err != nil {
			return err
		}
		proposalDir := filepath.Join(c.gitRepo, token, strconv.FormatUint(v, 10))

		// Convert git backend types to tstore backend types
		recordMD, err := c.convertRecordMetadata(proposalDir)
		if err != nil {
			return err
		}
		files, err := c.convertFiles(proposalDir)
		if err != nil {
			return err
		}
		proposalMD, err := c.convertProposalMetadata(proposalDir)
		if err != nil {
			return err
		}
		voteMD, err := c.convertVoteMetadata(proposalDir)
		if err != nil {
			return err
		}
		userMD, err := c.convertUserMetadata(proposalDir)
		if err != nil {
			return err
		}
		statusChanges, err := c.convertStatusChanges(proposalDir)
		if err != nil {
			return err
		}
		ct, err := c.convertComments(proposalDir)
		if err != nil {
			return err
		}
		var (
			authDetails *ticketvote.AuthDetails
			voteDetails *ticketvote.VoteDetails
			castVotes   []ticketvote.CastVoteDetails
		)
		switch {
		case recordMD.Status != backend.StatusPublic:
			// Only proposals with a public status will have vote
			// data that needs to be converted. This proposal does
			// not have a public status so we can skip this part.

		default:
			// This proposal has vote data that needs to be converted
			authDetails, err = c.convertAuthDetails(proposalDir)
			if err != nil {
				return err
			}
			voteDetails, err = c.convertVoteDetails(proposalDir, voteMD)
			if err != nil {
				return err
			}
			castVotes, err = c.convertCastVotes(proposalDir)
			if err != nil {
				return err
			}
		}

		// Build the proposal
		p := proposal{
			RecordMetadata:   *recordMD,
			Files:            files,
			ProposalMetadata: *proposalMD,
			VoteMetadata:     voteMD,
			UserMetadata:     *userMD,
			StatusChanges:    statusChanges,
			CommentAdds:      ct.Adds,
			CommentDels:      ct.Dels,
			CommentVotes:     ct.Votes,
			AuthDetails:      authDetails,
			VoteDetails:      voteDetails,
			CastVotes:        castVotes,
		}
		err = verifyProposal(p)
		if err != nil {
			return err
		}

		// write the proposal to disk
		err = writeProposal(c.legacyDir, p)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Legacy proposal conversion complete\n")

	return nil
}

// convertRecordMetadata reads the git backend RecordMetadata from disk for
// the provided proposal and converts it into a tstore backend RecordMetadata.
func (c *convertCmd) convertRecordMetadata(proposalDir string) (*backend.RecordMetadata, error) {
	fmt.Printf("  RecordMetadata\n")

	// Read the git backend record metadata from disk
	fp := recordMetadataPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var r gitbe.RecordMetadata
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}

	// The version number can be found in the proposal
	// file path. It is the last directory in the path.
	v := filepath.Base(proposalDir)
	version, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, err
	}

	// Convert the record metadata
	rm := convertRecordMetadata(r, uint32(version))

	fmt.Printf("    Token    : %v\n", rm.Token)
	fmt.Printf("    Version  : %v\n", rm.Version)
	fmt.Printf("    Iteration: %v\n", rm.Iteration)
	fmt.Printf("    State    : %v\n", backend.States[rm.State])
	fmt.Printf("    Status   : %v\n", backend.Statuses[rm.Status])
	fmt.Printf("    Timestamp: %v\n", rm.Timestamp)
	fmt.Printf("    Merkle   : %v\n", rm.Merkle)

	return &rm, nil
}

// convertFiles reads all of the git backend proposal index file and image
// attachments from disk for the provided proposal and converts them to tstore
// backend files.
func (c *convertCmd) convertFiles(proposalDir string) ([]backend.File, error) {
	fmt.Printf("  Files\n")

	files := make([]backend.File, 0, 64)

	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	files = append(files, convertFile(b, pi.FileNameIndexFile))

	fmt.Printf("    %v\n", pi.FileNameIndexFile)

	// Read any image attachments from disk
	attachments, err := parseProposalAttachmentFilenames(proposalDir)
	if err != nil {
		return nil, err
	}
	for _, fn := range attachments {
		fp := attachmentFilePath(proposalDir, fn)
		b, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, err
		}

		files = append(files, convertFile(b, fn))

		fmt.Printf("    %v\n", fn)
	}

	return files, nil
}

// convertProposalMetadata reads the git backend data from disk that is
// required to build the pi plugin ProposalMetadata structure, then returns the
// ProposalMetadata.
func (c *convertCmd) convertProposalMetadata(proposalDir string) (*pi.ProposalMetadata, error) {
	fmt.Printf("  Proposal metadata\n")

	// The only data we need to pull from the legacy
	// proposal is the proposal name. The name will
	// always be the first line of the proposal index
	// file.
	name, err := parseProposalName(proposalDir)
	if err != nil {
		return nil, err
	}

	pm := convertProposalMetadata(name)

	fmt.Printf("    Name       : %v\n", pm.Name)

	return &pm, nil
}

// convertVoteMetadata reads the git backend data from disk that is required to
// build a ticketvote plugin VoteMetadata structure, then returns the
// VoteMetadata.
func (c *convertCmd) convertVoteMetadata(proposalDir string) (*ticketvote.VoteMetadata, error) {
	fmt.Printf("  Vote metadata\n")

	// The vote metadata fields are in the gitbe
	// proposal metadata payload file. This file
	// will only exist for some gitbe proposals.
	fp := proposalMetadataPath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Read the proposal metadata file from disk
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	var pm gitbe.ProposalMetadata
	err = json.Unmarshal(b, &pm)
	if err != nil {
		return nil, err
	}

	// A VoteMetadata only needs to be built if the proposal
	// contains fields that indicate that it's either an RFP
	// or RFP submissions. These are the LinkBy and LinkTo
	// fields.
	if pm.LinkBy == 0 && pm.LinkTo == "" {
		// We don't need a VoteMetadata for this proposal
		return nil, nil
	}

	// Build the vote metadata
	vm := convertVoteMetadata(pm)

	fmt.Printf("    Link by: %v\n", vm.LinkBy)
	fmt.Printf("    Link to: %v\n", vm.LinkTo)

	return &vm, nil
}

// convertUserMetadata reads the git backend data from disk that is required to
// build a usermd plugin UserMetadata structure, then returns the UserMetadata.
//
// This function makes an external API call to the politeia API to retrieve the
// user ID.
func (c *convertCmd) convertUserMetadata(proposalDir string) (*usermd.UserMetadata, error) {
	fmt.Printf("  User metadata\n")

	// Read the proposal general mdstream from disk
	fp := proposalGeneralPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// We can decode both the v1 and v2 proposal general
	// metadata stream into the ProposalGeneralV2 struct
	// since the fields we need from it are present in
	// both versions.
	var p gitbe.ProposalGeneralV2
	err = json.Unmarshal(b, &p)
	if err != nil {
		return nil, err
	}

	// Populate the user ID. The user ID was not saved
	// to disk in the git backend, so we must retrieve
	// it from the politeia API using the public key.
	userID, err := c.userIDByPubKey(p.PublicKey)
	if err != nil {
		return nil, err
	}

	// Build the user metadata
	um := convertUserMetadata(p, userID)

	fmt.Printf("    User ID  : %v\n", um.UserID)
	fmt.Printf("    PublicKey: %v\n", um.PublicKey)
	fmt.Printf("    Signature: %v\n", um.Signature)

	return &um, nil
}

// convertStatusChanges reads the git backend data from disk that is required
// to build the usermd plugin StatusChangeMetadata structures, then returns
// the StateChangeMetadata that is found.
//
// A public proposal will only have one status change returned. The status
// change of when the proposal was made public.
//
// An abandoned proposal will have two status changes returned. The status
// change from when the proposal was made public and the status change from
// when the proposal was marked as abandoned.
//
// All other status changes are not public data and thus will not have been
// included in the legacy git repo.
func (c *convertCmd) convertStatusChanges(proposalDir string) ([]usermd.StatusChangeMetadata, error) {
	fmt.Printf("  Status changes\n")

	// Read the status changes mdstream from disk
	fp := statusChangesPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// Parse the token and version from the proposal dir path
	token, ok := parseProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}
	version, err := parseProposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// The git backend v1 status change struct does not have the
	// signature included. This is the only difference between
	// v1 and v2, so we decode all of them into the v2 structure.
	var (
		statuses = make([]usermd.StatusChangeMetadata, 0, 16)
		decoder  = json.NewDecoder(bytes.NewReader(b))
	)
	for {
		var sc gitbe.RecordStatusChangeV2
		err := decoder.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		statuses = append(statuses, convertStatusChange(sc, token, version))
	}

	// Sort status changes from oldest to newest
	sort.SliceStable(statuses, func(i, j int) bool {
		return statuses[i].Timestamp < statuses[j].Timestamp
	})

	// Sanity checks
	switch {
	case len(statuses) == 0:
		return nil, fmt.Errorf("no status changes found")
	case len(statuses) > 2:
		return nil, fmt.Errorf("invalid number of status changes (%v)",
			len(statuses))
	}
	for _, v := range statuses {
		switch v.Status {
		case 2:
			// Public status. This is expected.
		case 4:
			// Abandoned status. This is expected.
		default:
			return nil, fmt.Errorf("invalid status %v", v.Status)
		}
	}

	// Print the status changes
	for i, v := range statuses {
		status := backend.Statuses[backend.StatusT(v.Status)]
		fmt.Printf("    Token    : %v\n", v.Token)
		fmt.Printf("    Version  : %v\n", v.Version)
		fmt.Printf("    Status   : %v\n", status)
		fmt.Printf("    PublicKey: %v\n", v.PublicKey)
		fmt.Printf("    Signature: %v\n", v.Signature)
		fmt.Printf("    Reason   : %v\n", v.Reason)
		fmt.Printf("    Timestamp: %v\n", v.Timestamp)

		if i != len(statuses)-1 {
			fmt.Printf("    ----\n")
		}
	}

	return statuses, nil
}

// commentTypes contains the various comment data types for a proposal.
type commentTypes struct {
	Adds  []comments.CommentAdd
	Dels  []comments.CommentDel
	Votes []comments.CommentVote
}

// convertComments converts a legacy proposal's comment data from git backend
// types to tstore backend types. This process included reading the comments
// journal from disk, converting the comment types, and retrieving the user ID
// from politeia for each comment and comment vote.
//
// Note, the comment signature messages changed between the git backend and the
// tstore backend.
func (c *convertCmd) convertComments(proposalDir string) (*commentTypes, error) {
	fmt.Printf("  Comments\n")

	// Open the comments journal
	fp := commentsJournalPath(proposalDir)
	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the journal line-by-line and decode the payloads
	var (
		scanner = bufio.NewScanner(f)

		// The legacy proposals may contain duplicate comments.
		// We filter these duplicates out by storing them in a
		// map where the comment signature is the key.
		adds  = make(map[string]comments.CommentAdd)  // [sig]CommentAdd
		dels  = make(map[string]comments.CommentDel)  // [sig]CommentDel
		votes = make(map[string]comments.CommentVote) // [sig]CommentVote

		// We must track the parent IDs for new comments
		// because the gitbe censore comment struct does
		// include the parent ID, but the comments plugin
		// del struct does.
		parentIDs = make(map[string]uint32) // [commentID]parentID
	)
	for scanner.Scan() {
		// Decode the current line
		r := bytes.NewReader(scanner.Bytes())
		d := json.NewDecoder(r)

		// Decode the action
		var a gitbe.JournalAction
		err := d.Decode(&a)
		if err != nil {
			return nil, err
		}

		// Decode the journal entry
		switch a.Action {
		case gitbe.JournalActionAdd:
			var cm gitbe.Comment
			err = d.Decode(&cm)
			if err != nil {
				return nil, err
			}
			userID, err := c.userIDByPubKey(cm.PublicKey)
			if err != nil {
				return nil, err
			}
			ca := convertCommentAdd(cm, userID)
			adds[ca.Signature] = ca

			// Save the parent ID
			parentIDs[cm.CommentID] = ca.ParentID

		case gitbe.JournalActionDel:
			var cc gitbe.CensorComment
			err = d.Decode(&cc)
			if err != nil {
				return nil, err
			}
			userID, err := c.userIDByPubKey(cc.PublicKey)
			if err != nil {
				return nil, err
			}
			parentID, ok := parentIDs[cc.CommentID]
			if !ok {
				return nil, fmt.Errorf("parent id not found for %v", cc.CommentID)
			}
			dels[cc.Signature] = convertCommentDel(cc, parentID, userID)

		case gitbe.JournalActionAddLike:
			var lc gitbe.LikeComment
			err = d.Decode(&lc)
			if err != nil {
				return nil, err
			}
			userID, err := c.userIDByPubKey(lc.PublicKey)
			if err != nil {
				return nil, err
			}
			votes[lc.Signature] = convertCommentVote(lc, userID)

		default:
			return nil, fmt.Errorf("invalid action '%v'", a.Action)
		}
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	fmt.Printf("    Parsed %v comment adds\n", len(adds))
	fmt.Printf("    Parsed %v comment dels\n", len(dels))
	fmt.Printf("    Parsed %v comment votes\n", len(votes))

	// Convert the maps into slices and sort them by timestamp
	// from oldest to newest.
	var (
		sortedAdds  = make([]comments.CommentAdd, 0, len(adds))
		sortedDels  = make([]comments.CommentDel, 0, len(dels))
		sortedVotes = make([]comments.CommentVote, 0, len(votes))
	)
	for _, v := range adds {
		sortedAdds = append(sortedAdds, v)
	}
	for _, v := range dels {
		sortedDels = append(sortedDels, v)
	}
	for _, v := range votes {
		sortedVotes = append(sortedVotes, v)
	}
	sort.SliceStable(sortedAdds, func(i, j int) bool {
		return sortedAdds[i].Timestamp < sortedAdds[j].Timestamp
	})
	sort.SliceStable(sortedDels, func(i, j int) bool {
		return sortedDels[i].Timestamp < sortedDels[j].Timestamp
	})
	sort.SliceStable(sortedVotes, func(i, j int) bool {
		return sortedVotes[i].Timestamp < sortedVotes[j].Timestamp
	})

	return &commentTypes{
		Adds:  sortedAdds,
		Dels:  sortedDels,
		Votes: sortedVotes,
	}, nil
}

// convertAuthDetails reads the git backend data from disk that is required to
// build a ticketvote plugin AuthDetails structure, then returns the
// AuthDetails.
func (c *convertCmd) convertAuthDetails(proposalDir string) (*ticketvote.AuthDetails, error) {
	fmt.Printf("  AuthDetails\n")

	// Verify that an authorize vote mdstream exists.
	// This will not exist for some proposals, e.g.
	// abandoned proposals.
	fp := authorizeVotePath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Read the authorize vote mdstream from disk
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	var av gitbe.AuthorizeVote
	err = json.Unmarshal(b, &av)
	if err != nil {
		return nil, err
	}

	// Parse the token and version from the proposal dir path
	token, ok := parseProposalToken(proposalDir)
	if !ok {
		return nil, fmt.Errorf("token not found in path '%v'", proposalDir)
	}
	if av.Token != token {
		return nil, fmt.Errorf("auth vote token invalid: got %v, want %v",
			av.Token, token)
	}
	version, err := parseProposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// Build the ticketvote AuthDetails
	ad := ticketvote.AuthDetails{
		Token:     av.Token,
		Version:   version,
		Action:    av.Action,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
		Timestamp: av.Timestamp,
		Receipt:   av.Receipt,
	}

	// Verify signatures
	adv1 := convertAuthDetailsToV1(ad)
	err = client.AuthDetailsVerify(adv1, gitbe.PublicKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("    Token    : %v\n", ad.Token)
	fmt.Printf("    Version  : %v\n", ad.Version)
	fmt.Printf("    Action   : %v\n", ad.Action)
	fmt.Printf("    PublicKey: %v\n", ad.PublicKey)
	fmt.Printf("    Signature: %v\n", ad.Signature)
	fmt.Printf("    Timestamp: %v\n", ad.Timestamp)
	fmt.Printf("    Receipt  : %v\n", ad.Receipt)

	return &ad, nil
}

// convertVoteDetails reads the git backend data from disk that is required to
// build a ticketvote plugin VoteDetails structure, then returns the
// VoteDetails.
func (c *convertCmd) convertVoteDetails(proposalDir string, voteMD *ticketvote.VoteMetadata) (*ticketvote.VoteDetails, error) {
	fmt.Printf("  Vote details\n")

	// Verify that vote mdstreams exists. These
	// will not exist for some proposals, such
	// as abandoned proposals.
	fp := startVotePath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist. No need to continue.
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Read the start vote from disk
	startVoteJSON, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	// Read the start vote reply from disk
	fp = startVoteReplyPath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}
	var svr gitbe.StartVoteReply
	err = json.Unmarshal(b, &svr)
	if err != nil {
		return nil, err
	}

	// Pull the proposal version from the proposal dir path
	version, err := parseProposalVersion(proposalDir)
	if err != nil {
		return nil, err
	}

	// Build the vote details
	vd := convertVoteDetails(startVoteJSON, svr, version, voteMD)

	fmt.Printf("    Token       : %v\n", vd.Params.Token)
	fmt.Printf("    Version     : %v\n", vd.Params.Version)
	fmt.Printf("    Type        : %v\n", vd.Params.Type)
	fmt.Printf("    Mask        : %v\n", vd.Params.Mask)
	fmt.Printf("    Duration    : %v\n", vd.Params.Duration)
	fmt.Printf("    Quorum      : %v\n", vd.Params.QuorumPercentage)
	fmt.Printf("    Pass        : %v\n", vd.Params.PassPercentage)
	fmt.Printf("    Options     : %+v\n", vd.Params.Options)
	fmt.Printf("    Parent      : %v\n", vd.Params.Parent)
	fmt.Printf("    Start height: %v\n", vd.StartBlockHeight)
	fmt.Printf("    Start hash  : %v\n", vd.StartBlockHash)
	fmt.Printf("    End height  : %v\n", vd.EndBlockHeight)

	return &vd, nil
}

// convertCastVotes reads the git backend data from disk that is required to
// build the ticketvote plugin CastVoteDetails structures, then returns the
// CastVoteDetails slice.
//
// This process includes parsing the ballot journal from the git repo,
// retrieving the commitment addresses from dcrdata for each vote, and parsing
// the git commit log to associate each vote with a commit timestamp.
func (c *convertCmd) convertCastVotes(proposalDir string) ([]ticketvote.CastVoteDetails, error) {
	fmt.Printf("  Cast votes\n")

	// Verify that the ballots journal exists. This
	/// will not exist for some proposals, such as
	// abandoned proposals.
	fp := ballotsJournalPath(proposalDir)
	if _, err := os.Stat(fp); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			// File does not exist
			return nil, nil

		default:
			// Unknown error
			return nil, err
		}
	}

	// Open the ballots journal
	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the journal line-by-line
	var (
		scanner = bufio.NewScanner(f)

		// There are some duplicate votes in early proposals due to
		// a bug. Use a map here so that duplicate votes are removed.
		//
		// map[ticket]CastVoteDetails
		votes = make(map[string]gitbe.CastVoteJournal, 40960)

		// Ticket hashes of all cast votes. These are used to
		// fetch the largest commitment address for each ticket.
		tickets = make([]string, 0, 40960)
	)
	for scanner.Scan() {
		// Decode the current line
		r := bytes.NewReader(scanner.Bytes())
		d := json.NewDecoder(r)

		var j gitbe.JournalAction
		err := d.Decode(&j)
		if err != nil {
			return nil, err
		}
		if j.Action != gitbe.JournalActionAdd {
			return nil, fmt.Errorf("invalid action '%v'", j.Action)
		}

		var cvj gitbe.CastVoteJournal
		err = d.Decode(&cvj)
		if err != nil {
			return nil, err
		}

		// Save the cast vote
		votes[cvj.CastVote.Ticket] = cvj
		tickets = append(tickets, cvj.CastVote.Ticket)
	}
	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	fmt.Printf("    Parsed %v vote journal entries\n", len(votes))

	// Fetch largest commitment address for each vote
	caddrs, err := c.commitmentAddrs(tickets)
	if err != nil {
		return nil, err
	}

	// Parse the vote timestamps. These are not the timestamps
	// of when the vote was actually cast, but rather the
	// timestamp of when the vote was committed to the git
	// repo. This is the most accurate timestamp that we have.
	voteTS, err := parseVoteTimestamps(proposalDir)
	if err != nil {
		return nil, err
	}

	// Convert the votes
	castVotes := make([]ticketvote.CastVoteDetails, 0, len(votes))
	for ticket, vote := range votes {
		caddr, ok := caddrs[ticket]
		if !ok {
			return nil, fmt.Errorf("commitment address not found for %v", ticket)
		}
		ts, ok := voteTS[ticket]
		if !ok {
			return nil, fmt.Errorf("timestamp not found for vote %v", ticket)
		}
		cv := convertCastVoteDetails(vote, caddr, ts)
		castVotes = append(castVotes, cv)
	}

	// Sort the votes from oldest to newest
	sort.SliceStable(castVotes, func(i, j int) bool {
		return castVotes[i].Timestamp < castVotes[j].Timestamp
	})

	// Tally votes and print the vote statistics
	results := make(map[string]int)
	for _, v := range castVotes {
		results[v.VoteBit]++
	}
	var total int
	for voteBit, voteCount := range results {
		fmt.Printf("    %v    : %v\n", voteBit, voteCount)
		total += voteCount
	}
	fmt.Printf("    Total: %v\n", total)

	// Verify all cast vote signatures
	for i, v := range castVotes {
		s := fmt.Sprintf("    Verifying cast vote signature %v/%v",
			i+1, len(votes))
		printInPlace(s)

		voteV1 := convertCastVoteDetailsToV1(v)
		err = client.CastVoteDetailsVerify(voteV1, gitbe.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	fmt.Printf("\n")

	return castVotes, nil
}

// userIDByPubKey retrieves and returns the user ID from the politeia API for
// the provided public key. The results are cached in memory.
func (c *convertCmd) userIDByPubKey(userPubKey string) (string, error) {
	userID := c.getUserIDByPubKey(userPubKey)
	if userID != "" {
		return userID, nil
	}
	u, err := userByPubKey(c.client, userPubKey)
	if err != nil {
		return "", err
	}
	if u.ID == "" {
		return "", fmt.Errorf("user id not found")
	}
	c.setUserIDByPubKey(userPubKey, u.ID)
	return u.ID, nil
}

func (c *convertCmd) setUserIDByPubKey(pubKey, userID string) {
	c.Lock()
	defer c.Unlock()

	c.userIDs[pubKey] = userID
}

func (c *convertCmd) getUserIDByPubKey(pubKey string) string {
	c.Lock()
	defer c.Unlock()

	return c.userIDs[pubKey]
}

// parseProposalName parses and returns the proposal name from the proposal
// index file.
func parseProposalName(proposalDir string) (string, error) {
	// Read the index file from disk
	fp := indexFilePath(proposalDir)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", err
	}

	// Parse the proposal name from the index file. The
	// proposal name will always be the first line of the
	// file.
	r := bufio.NewReader(bytes.NewReader(b))
	name, _, err := r.ReadLine()
	if err != nil {
		return "", err
	}

	return string(name), nil
}

// convertCastVoteDetailsToV1 converts a cast vote details from the plugin type
// to the API type so that we can use the API provided method to verify the
// signature. The data structures are exactly the same.
func convertCastVoteDetailsToV1(vote ticketvote.CastVoteDetails) v1.CastVoteDetails {
	return v1.CastVoteDetails{
		Token:     vote.Token,
		Ticket:    vote.Ticket,
		VoteBit:   vote.VoteBit,
		Address:   vote.Address,
		Signature: vote.Signature,
		Receipt:   vote.Receipt,
		Timestamp: vote.Timestamp,
	}
}

// convertAuthDetailsToV1 converts a auth details from the plugin type to the
// API type so that we can use the API provided methods to verify the
// signature. The data structures are exactly the same.
func convertAuthDetailsToV1(a ticketvote.AuthDetails) v1.AuthDetails {
	return v1.AuthDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    a.Action,
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: a.Timestamp,
		Receipt:   a.Receipt,
	}
}
