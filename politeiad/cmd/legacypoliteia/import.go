// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/subosito/gozaru"
)

const (
	dataDescriptorCastVoteDetails   = ticketvote.PluginID + "-castvote-v1"
	dataDescriptorVoteCollider      = ticketvote.PluginID + "-vcollider-v1"
	dataDescriptorAuthDetails       = ticketvote.PluginID + "-auth-v1"
	dataDescriptorVoteDetails       = ticketvote.PluginID + "-vote-v1"
	dataDescriptorStartRunoffRecord = ticketvote.PluginID + "-startrunoff-v1"

	dataDescriptorCommentAdd  = comments.PluginID + "-add-v1"
	dataDescriptorCommentDel  = comments.PluginID + "-del-v1"
	dataDescriptorCommentVote = comments.PluginID + "-vote-v1"
)

// importProposals walks the import directory and imports the legacy proposals
// into tstore. It accomplishes this using the following steps:
//
// 1. Inventory all of the legacy proposals being imported.
//
// 2. Retrieve the tstore token inventory.
//
// 3. Iterate through each record in the existing tstore inventory and check
//    if the record corresponds to one of the legacy proposals.
//
// 4. An fsck is performed on all proposals that have been found to already
//    exist in tstore to verify that the full legacy proposal has been
//    imported.  Any missing legacy proposal content is added to tstore. This
//    can happen if the import command was previously being run and was stopped
//    prior to fully importing the proposal or if the command encountered an
//    unexpected error.
//
// 5. Add all remaining legacy RFP proposals to tstore. This must be done first
//    so that the RFP submissions can link to the tstore RFP proposal token.
//
// 6. Add all remaining proposals to tstore.
func importProposals(legacyDir string, cmd *importCmd) error {
	var (
		rfps []proposal
		rest []proposal
	)
	// Inventory all of the legacy proposals being imported
	err := filepath.Walk(legacyDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// filepath.Walk() walks the directory tree including the root,
			// skip it.
			if path == legacyDir {
				return nil
			}

			// Read json content and unmarshal proposal struct
			jsonFile, err := os.Open(path)
			if err != nil {
				return err
			}
			b, err := ioutil.ReadAll(jsonFile)
			if err != nil {
				return err
			}
			var prop proposal
			err = json.Unmarshal(b, &prop)
			if err != nil {
				return err
			}

			switch {
			case prop.VoteMetadata != nil && prop.VoteMetadata.LinkBy != 0:
				// Current proposal is a RFP, collect it in a separate slice in
				// order to import RFPs first, so we could update their submissions
				// _parent_ references before inserting the submissions into tstore.
				rfps = append(rfps, prop)

				// Store RFP startRunoffRecord so we could import it later when we
				// are done importing the RFP submissions.
				storeStartRunoffRecord(prop.RecordMetadata.Token,
					prop.VoteDetails, cmd)

			case prop.VoteMetadata != nil && prop.VoteMetadata.LinkTo != "":
				// Current proposal is a RFP submission, add proposal token to the
				// startRunoffRecord submissions list.
				collectRFPSubmissionToken(prop.VoteMetadata.LinkTo,
					prop.RecordMetadata.Token, cmd)

				rest = append(rest, prop)

			default:
				//  Current proposal is a standard proposal
				rest = append(rest, prop)
			}

			return nil
		})
	if err != nil {
		return err
	}

	// Collect rfp legacy tokens
	rfpTokens := make([]string, 0, len(rfps))
	for _, rfp := range rfps {
		rfpTokens = append(rfpTokens, rfp.RecordMetadata.Token)
	}

	// XXX Add fsck step here!

	// Import missing legacy RFPs into tstore concurrently
	importProposalsConcurrently(legacyDir, rfps, cmd)

	// Import missing standard proposals & RFP submissions into tstore
	// concurrently.
	importProposalsConcurrently(legacyDir, rest, cmd)

	// Update RFP submissions tstore tokens in the RFPs startRunoffRecord
	// structs.
	err = updateRFPSubmissionsTokens(rfpTokens, cmd)
	if err != nil {
		return err
	}

	// Import startRunoffRecords
	err = importStartRunoffRecords(cmd)
	if err != nil {
		return err
	}

	return nil
}

// storeStartRunoffRecord accepts a legacy token of a RFP and it's vote
// details struct, it stores the vote details information into the RFP's
// startRunoffRecord struct in memory.
func storeStartRunoffRecord(rfpToken string, vd *ticketvote.VoteDetails, cmd *importCmd) {
	var srr *startRunoffRecord
	if srr = cmd.getStartRunoffRecord(rfpToken); srr == nil {
		// No startRunoffRecord was found for the given RFP token, initiate
		// new one with empty Submissions field which will be populated
		// with the tokens when parsing the submissions. It will be updated
		// with the tstore tokens when the submissions are imported to the
		// tstore, only then the startRunoffRecord blobs will be ready to be
		// imported.
		srr = &startRunoffRecord{
			Submissions: []string{},
		}
	}
	// Populate vote details fields
	srr.Mask = vd.Params.Mask
	srr.Duration = vd.Params.Duration
	srr.QuorumPercentage = vd.Params.QuorumPercentage
	srr.PassPercentage = vd.Params.PassPercentage
	srr.StartBlockHeight = vd.StartBlockHeight
	srr.StartBlockHash = vd.StartBlockHash
	srr.EndBlockHeight = vd.EndBlockHeight
	srr.EligibleTickets = vd.EligibleTickets

	cmd.setStartRunoffRecord(rfpToken, srr)
}

// collectRFPSubmissionToken adds the given RFP submission token to Submissions
// field of the RFP's startRunoffRecord struct.
func collectRFPSubmissionToken(rfpToken, submissionToken string, cmd *importCmd) {
	var srr *startRunoffRecord
	if srr = cmd.getStartRunoffRecord(rfpToken); srr == nil {
		// RFP has no startRunoffRecord yet, initiate a new one. this func only
		// populates the Submissions field, all other fields will be populated
		// in later stage when we meet the legacy RFP directory.
		srr = &startRunoffRecord{
			Submissions: []string{},
		}
	}
	srr.Submissions = append(srr.Submissions, submissionToken)
	cmd.setStartRunoffRecord(rfpToken, srr)
}

// importStartRunoffRecords imports all the startRunoffRecord blobs found in
// memory into tstore.
func importStartRunoffRecords(cmd *importCmd) error {
	cmd.Lock()
	defer cmd.Unlock()

	fmt.Printf("Importing startRunoffRecords\n")
	for gitToken, sr := range cmd.startRunoffRecords {
		tstoreToken := cmd.tstoreTokens[gitToken]
		if tstoreToken == "" {
			return errors.Errorf("RFP tstore token was not found while importing "+
				"startRunoffRecords; RFP token: %v", gitToken)
		}
		b, err := hex.DecodeString(tstoreToken)
		if err != nil {
			return err
		}

		saveBlobsConcurrently([]interface{}{sr}, dataDescriptorStartRunoffRecord,
			b, cmd)
	}

	fmt.Printf("Imported startRunoffRecords successfully\n")
	return nil
}

// updateRFPSubmissionsTokens replaces RFP submissions' legacy tokens stored
// in memory with the RFP submissions' new tstore tokens.
func updateRFPSubmissionsTokens(rfpTokens []string, cmd *importCmd) error {
	for _, rfpToken := range rfpTokens {
		srr := cmd.getStartRunoffRecord(rfpToken)
		// Update submissions tokens with their new tlog tokens.
		var subs []string
		for _, s := range srr.Submissions {
			tstoreToken := cmd.getTstoreToken(s)
			if tstoreToken == "" {
				return errors.Errorf("RFP submission tstore token not found: %v", s)
			}
			subs = append(subs, tstoreToken)
		}
		srr.Submissions = subs

		cmd.setStartRunoffRecord(rfpToken, srr)
		fmt.Printf("Updated RFP %v submissions tokens\n", rfpToken)
	}

	return nil
}

// importProposalsConcurrently imports the given proposals into tstore
// concurrently.
func importProposalsConcurrently(legacyDir string, props []proposal, cmd *importCmd) {
	var wg sync.WaitGroup
	for _, prop := range props {
		// Increment the wait group.
		wg.Add(1)

		// Spin routine to import proposal.
		go func(p proposal) {
			// Decrement the wait group once the proposal has been imported
			defer wg.Done()

			// Import proposal
			err := importProposal(&p, cmd)
			if err != nil {
				panic(err)
			}
		}(prop)
	}

	// Wait for all proposal imports to finish
	wg.Wait()
}

// importProposal imports the specified legacy proposal into tstore.
//
// This function assumes that the proposal does not yet exist in tstore.
// Handling proposals that have been partially added is done by the
// fsckProposal() function.
//
// The steps this function executes to accomplish the import are the following:
//
// 1. Create a new tlog tree for the legacy proposal.
//
// 2. Replace the git backend tokens with the tstore backend token in the
//    following structures:
//      - Record Metadata
//      - Vote Details Params
//      - Vote Metadata LinkTo
//
// 3. Import auth details blob.
//
// 4. Import vote details blob.
//
// 5. Import comment blobs and vote blobs concurrently. This is the most costly
//    process of importing, and is why it is done concurrently.
//
// 6. Add git token to tstore token mapping to the memory cache for all RFP
// 	  parent proposals. The parent token of all RFP submissions are updated
//    with the tstore RFP parent token.
func importProposal(prop *proposal, cmd *importCmd) error {
	gitToken := prop.RecordMetadata.Token
	fmt.Printf("Importing legacy proposal: %v\n", gitToken)

	// Create a new tlog tree for the legacy record
	token, err := cmd.tstoreClient.Tstore.RecordNew()
	if err != nil {
		return err
	}

	// Replace gitbe tokens with the new tstorebe token

	// Replace record metadata token
	prop.RecordMetadata.Token = hex.EncodeToString(token)
	if prop.VoteDetails != nil {
		// Proposal has vote details metadata, replace params token
		prop.VoteDetails.Params.Token = hex.EncodeToString(token)
	}
	if prop.VoteMetadata != nil && prop.VoteMetadata.LinkTo != "" {
		// Proposal is a RFP submission, replace linkTo with the new tstore
		// token of its RFP parent.
		t := cmd.getTstoreToken(prop.VoteMetadata.LinkTo)
		if t == "" {
			return errors.Errorf("tstore token for RFP parent %v not found "+
				"in cache while parsing the RFP submission %v",
				prop.VoteMetadata.LinkTo, prop.RecordMetadata.Token)
		}
		legacyToken := prop.VoteMetadata.LinkTo
		prop.VoteMetadata.LinkTo = t
		prop.VoteDetails.Params.Parent = t

		fmt.Printf("RFP submission parent token %v was replaced with "+
			"the new tstore token %v\n", legacyToken, prop.VoteMetadata.LinkTo)
	}

	// Save proposal to tstore
	err = importRecord(prop, token, cmd)
	if err != nil {
		return err
	}

	// Save auth details blob to tstore
	err = importAuthDetails(prop.AuthDetails, token, cmd)
	if err != nil {
		return err
	}

	// Save vote details blob to tstore
	err = importVoteDetails(prop.VoteDetails, token, cmd)
	if err != nil {
		return err
	}

	// Save comment blobs to tstore concurrently
	importComments(prop, token, cmd)

	// Save vote blbos to tstore concurrently
	importVotes(prop, token, cmd)

	// Set git token to tstore token mapping
	cmd.setTstoreToken(gitToken, hex.EncodeToString(token))

	fmt.Printf("Legacy proposal %v imported successfully; new token: %v\n",
		gitToken, hex.EncodeToString(token))

	return nil
}

// importRecord saves the proposal that was read from the json file into
// tstore. This function also prepares the backend files and metadata streams
// that are contained in the proposal struct.
func importRecord(p *proposal, tstoreToken []byte, cmd *importCmd) error {
	// Prepare proposal metadata file.
	b, err := json.Marshal(p.ProposalMetadata)
	if err != nil {
		return err
	}
	pm := &backend.File{
		Name:    "proposalmetadata.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
	}
	p.Files = append(p.Files, *pm)

	// Prepare vote metadata file, if needed.
	if p.VoteMetadata.LinkBy != 0 || p.VoteMetadata.LinkTo != "" {
		b, err := json.Marshal(p.VoteMetadata)
		if err != nil {
			return err
		}
		vmd := &backend.File{
			Name:    ticketvote.FileNameVoteMetadata,
			MIME:    mime.DetectMimeType(b),
			Digest:  hex.EncodeToString(util.Digest(b)),
			Payload: base64.StdEncoding.EncodeToString(b),
		}
		p.Files = append(p.Files, *vmd)
	}

	// Create the metadata streams for the proposal.
	var metadatas []backend.MetadataStream

	// Prepare status changes metadata streams.
	for _, scmd := range p.StatusChanges {
		b, err := json.Marshal(scmd)
		if err != nil {
			return err
		}
		scmd := &backend.MetadataStream{
			PluginID: usermd.PluginID,
			StreamID: usermd.StreamIDStatusChanges,
			Payload:  string(b),
		}
		metadatas = append(metadatas, *scmd)
	}

	// Prepare user metadata stream.
	b, err = json.Marshal(p.UserMetadata)
	if err != nil {
		return err
	}
	umd := &backend.MetadataStream{
		PluginID: usermd.PluginID,
		StreamID: usermd.StreamIDUserMetadata,
		Payload:  string(b),
	}
	metadatas = append(metadatas, *umd)

	// Verify metadata streams and files data.
	err = metadataStreamsVerify(metadatas)
	if err != nil {
		return err
	}
	err = filesVerify(p.Files, nil)
	if err != nil {
		return err
	}

	// Verify user metadata
	/*err = userMetadataVerify(p.UserMetadata, p.Files)
	if err != nil {
		return err
	}*/

	// Check if record status is public. If so, we need to first save it as
	// unreviewed, and then save it as public. This is done to bypass the
	// validations from the RecordSave function.
	isPublic := false
	if p.RecordMetadata.Status == backend.StatusPublic {
		isPublic = true
		p.RecordMetadata.Status = backend.StatusUnreviewed
	}

	// Hardcode version and iteration to 1.
	p.RecordMetadata.Version = 1
	p.RecordMetadata.Iteration = 1

	// Save record to tstore.
	err = cmd.tstoreClient.Tstore.RecordSave(tstoreToken, p.RecordMetadata,
		metadatas, p.Files)
	if err != nil {
		return err
	}

	// If public, update from unreviewed to public status.
	if isPublic {
		p.RecordMetadata.Status = backend.StatusPublic
		p.RecordMetadata.Iteration = 2
		err = cmd.tstoreClient.Tstore.RecordSave(tstoreToken, p.RecordMetadata,
			metadatas, p.Files)
		if err != nil {
			return err
		}
	}

	return nil
}

// userMetadataVerify parses a UserMetadata from the metadata streams and
// verifies its contents are valid.
func userMetadataVerify(um usermd.UserMetadata, files []backend.File) error {
	// Verify user ID
	_, err := uuid.Parse(um.UserID)
	if err != nil {
		return errors.Errorf("invalid user ID")
	}

	// Verify signature
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	m, err := util.MerkleRoot(digests)
	if err != nil {
		return err
	}
	mr := hex.EncodeToString(m[:])
	err = util.VerifySignature(um.Signature, um.PublicKey, mr)
	if err != nil {
		return err
	}

	return nil
}

// metadataStreamsVerify verifies that all provided metadata streams are sane.
func metadataStreamsVerify(metadata []backend.MetadataStream) error {
	// Verify metadata
	md := make(map[string]map[uint32]struct{}, len(metadata))
	for i, v := range metadata {
		// Verify all fields are provided
		switch {
		case v.PluginID == "":
			e := fmt.Sprintf("plugin id missing at index %v", i)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		case v.StreamID == 0:
			e := fmt.Sprintf("stream id missing at index %v", i)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		case v.Payload == "":
			e := fmt.Sprintf("payload missing on %v %v", v.PluginID, v.StreamID)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		}

		// Verify no duplicates
		m, ok := md[v.PluginID]
		if !ok {
			m = make(map[uint32]struct{}, len(metadata))
			md[v.PluginID] = m
		}
		if _, ok := m[v.StreamID]; ok {
			e := fmt.Sprintf("%v %v", v.PluginID, v.StreamID)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamDuplicate,
				ErrorContext: e,
			}
		}

		// Add to metadata list
		m[v.StreamID] = struct{}{}
		md[v.PluginID] = m
	}

	return nil
}

// filesVerify verifies that all provided files are sane.
func filesVerify(files []backend.File, filesDel []string) error {
	// Verify files are being updated
	if len(files) == 0 && len(filesDel) == 0 {
		return backend.ContentError{
			ErrorCode: backend.ContentErrorFilesEmpty,
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			e := fmt.Sprintf("%v contains a file path", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			e := fmt.Sprintf("%v contains a file path", v)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}
	}

	// Prevent duplicate filenames
	fn := make(map[string]struct{}, len(files)+len(filesDel))
	for i := range files {
		if _, ok := fn[files[i].Name]; ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameDuplicate,
				ErrorContext: files[i].Name,
			}
		}
		fn[files[i].Name] = struct{}{}
	}
	for _, v := range filesDel {
		if _, ok := fn[v]; ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameDuplicate,
				ErrorContext: v,
			}
		}
		fn[v] = struct{}{}
	}

	// Prevent bad filenames
	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			e := fmt.Sprintf("%v is not sanitized", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}

		// Verify digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileDigestInvalid,
				ErrorContext: files[i].Name,
			}
		}

		// Verify payload is not empty
		if files[i].Payload == "" {
			e := fmt.Sprintf("%v payload empty", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFilePayloadInvalid,
				ErrorContext: e,
			}
		}

		// Decode base64 payload
		payload, err := base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			e := fmt.Sprintf("%v invalid base64", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFilePayloadInvalid,
				ErrorContext: e,
			}
		}

		// Calculate payload digest
		dp := util.Digest(payload)
		if !bytes.Equal(d[:], dp) {
			e := fmt.Sprintf("%v digest got %x, want %x",
				files[i].Name, d[:], dp)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileDigestInvalid,
				ErrorContext: e,
			}
		}

		// Verify MIME
		detectedMIMEType := mime.DetectMimeType(payload)
		if detectedMIMEType != files[i].MIME {
			e := fmt.Sprintf("%v mime got %v, want %v",
				files[i].Name, files[i].MIME, detectedMIMEType)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileMIMETypeInvalid,
				ErrorContext: e,
			}
		}

		if !mime.MimeValid(files[i].MIME) {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileMIMETypeUnsupported,
				ErrorContext: files[i].Name,
			}
		}
	}

	return nil
}

// importAuthDetails saves the auth details blob into tstore for the provided
// proposal token, if it exists.
func importAuthDetails(auth *ticketvote.AuthDetails, tstoreToken []byte, cmd *importCmd) error {
	// Save auth details blob, if it exists.
	if auth != nil {
		// Verify auth details signature.
		err := client.AuthDetailsVerify(convertAuthDetailsToV1(*auth),
			serverPubkey)
		if err != nil {
			return err
		}
		err = saveBlob(auth, dataDescriptorAuthDetails, tstoreToken, cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// importVoteDetails saves the vote details blob into tstore for the provided
// proposal token, if it exists.
func importVoteDetails(vote *ticketvote.VoteDetails, tstoreToken []byte, cmd *importCmd) error {
	// Save vote details blob, if it exists.
	if vote != nil {
		err := saveBlob(vote, dataDescriptorVoteDetails, tstoreToken, cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// importVotes saves all cast vote details blobs from the legacy proposal into
// tstore. For every cast vote blob, it also saves a vote collider blob. The
// blobs are saved concurrently.
func importVotes(p *proposal, tstoreToken []byte, cmd *importCmd) error {
	// Import cast vote details blob concurrently.
	err := importCastVoteDetails(p.CastVotes, tstoreToken, cmd)
	if err != nil {
		return err
	}

	// Import vote collider blob concurrently.
	importVoteCollider(p.CastVotes, tstoreToken, cmd)

	return nil
}

// importCastVoteDetails saves the given cast vote details into tstore for the
// provided proposal token.
func importCastVoteDetails(votes []ticketvote.CastVoteDetails, tstoreToken []byte, cmd *importCmd) error {
	votesParam := make([]interface{}, len(votes))
	for i, vote := range votes {
		// Verify cast vote details signature.
		err := client.CastVoteDetailsVerify(convertCastVoteDetailsToV1(vote),
			serverPubkey)
		if err != nil {
			return err
		}
		votesParam[i] = vote
	}
	saveBlobsConcurrently(votesParam, dataDescriptorCastVoteDetails, tstoreToken, cmd)

	return nil
}

// importVoteCollider saves a vote collider blob into tstore for the provided
// proposal token.
func importVoteCollider(votes []ticketvote.CastVoteDetails, tstoreToken []byte, cmd *importCmd) {
	collidersParam := make([]interface{}, len(votes))
	for i, vote := range votes {
		collidersParam[i] = voteCollider{
			Token:  hex.EncodeToString(tstoreToken),
			Ticket: vote.Ticket,
		}
	}
	saveBlobsConcurrently(collidersParam, dataDescriptorVoteCollider, tstoreToken, cmd)
}

// importComments saves all comment blobs from the legacy proposal into tstore.
// The blobs are saved concurrently.
func importComments(p *proposal, tstoreToken []byte, cmd *importCmd) {
	// Import comment add blobs concurrently.
	importCommentAdds(p.CommentAdds, tstoreToken, cmd)

	// Import comment del blobs concurrently.
	importCommentDels(p.CommentDels, tstoreToken, cmd)

	// Import comment vote blobs concurrently.
	importCommentVotes(p.CommentVotes, tstoreToken, cmd)
}

// importCommentAdds saves all comment add blobs for a legacy proposal into
// tstore. The blobs are saved concurrently on tstore.
func importCommentAdds(adds []comments.CommentAdd, tstoreToken []byte, cmd *importCmd) {
	addsParam := make([]interface{}, len(adds))
	for i, add := range adds {
		addsParam[i] = add
	}
	saveBlobsConcurrently(addsParam, dataDescriptorCommentAdd, tstoreToken, cmd)
}

// importCommentDels saves all comment del blobs from a legacy proposal into
// tstore.
func importCommentDels(dels []comments.CommentDel, tstoreToken []byte, cmd *importCmd) {
	delsParam := make([]interface{}, len(dels))
	for i, del := range dels {
		delsParam[i] = del
	}
	saveBlobsConcurrently(delsParam, dataDescriptorCommentDel, tstoreToken, cmd)
}

// importCommentVotes saves all comment vote blobs from a legacy proposal into
// tstore.
func importCommentVotes(votes []comments.CommentVote, tstoreToken []byte, cmd *importCmd) {
	votesParam := make([]interface{}, len(votes))
	for i, vote := range votes {
		votesParam[i] = vote
	}
	saveBlobsConcurrently(votesParam, dataDescriptorCommentVote, tstoreToken, cmd)
}

// saveBlob creates a new blob entry for the provided data and data descriptor,
// then saves it to tstore.
func saveBlob(data interface{}, dataDescriptor string, token []byte, cmd *importCmd) error {
	d, err := json.Marshal(data)
	if err != nil {
		return err
	}
	desc := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptor,
	}
	hint, err := json.Marshal(desc)
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, d)
	err = cmd.tstoreClient.BlobSave(token, be)
	if errors.Is(err, backend.ErrDuplicatePayload) {
		return errors.Errorf("Duplicate payload found. this should not" +
			"happen since duplicate blobs are handled by the convert cmd.")
	}
	if err != nil {
		return err
	}
	return nil
}

// saveBlobsConcurrently runs save blob concurrently. This is used to bypass
// the tstore signer limitation of saving blobs every 200ms. The number of
// routines is limited by the max routines constant.
func saveBlobsConcurrently(data []interface{}, dataDescriptor string, token []byte, cmd *importCmd) {
	var (
		batchSize = 10
		queue     = make([][]interface{}, 0, len(data)/batchSize)
		batch     = make([]interface{}, 0, batchSize)
	)
	// Setup the batches
	for _, v := range data {
		if len(batch) == batchSize {
			// The batch is full. Add it to the queue and start a new one.
			queue = append(queue, batch)
			batch = make([]interface{}, 0, batchSize)
		}
		batch = append(batch, v)
	}
	if len(batch) != 0 {
		// Add the leftover batch to the queue
		queue = append(queue, batch)
	}

	// Import the data. The contents of each batch are imported concurrently.
	for _, batch := range queue {
		var wg sync.WaitGroup
		for _, blob := range batch {
			// Increment the wait group.
			wg.Add(1)

			// Spin routine to import blob.
			go func(b interface{}) {
				// Decrement the wait group once the blob has been imported.
				defer wg.Done()

				// Save the blob to tstore.
				err := saveBlob(b, dataDescriptor, token, cmd)
				if err != nil {
					e := errors.Errorf("err:%v descritor:%v blob:%v",
						err, dataDescriptor, b)
					panic(e)
				}
			}(blob)
		}

		// Wait for the batch to finish before continuing to the next
		// on queue batch.
		wg.Wait()
	}
}
