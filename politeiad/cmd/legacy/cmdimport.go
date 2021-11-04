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
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
	"github.com/subosito/gozaru"
)

// cmdImport imports the dumped data contained in the provided import path.
// The command first walks through the path and pre parses data to help with
// the import. It handles RFP proposals by building the start runoff metadata,
// and by sorting which recrods will be imported first. RFP submissions need
// to reference their new tstore parent token, so they need to be inserted
// after their respective parents.
func (l *legacy) cmdImport(importPath string) error {
	var (
		records []*parsedData
		queue   []*parsedData
	)
	err := filepath.Walk(importPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// TODO: improve
			if path == "data" {
				return nil
			}

			// Open record's parsed data from json file and unmarshal.
			jsonFile, err := os.Open(path)
			if err != nil {
				return err
			}
			b, err := ioutil.ReadAll(jsonFile)
			if err != nil {
				return err
			}
			var data parsedData
			err = json.Unmarshal(b, &data)
			if err != nil {
				return err
			}

			// First, check if record is a RFP Parent. If so, save the start
			// runoff blob to be saved later on.
			if data.VoteMd.LinkBy != 0 {
				l.Lock()
				if _, ok := l.rfpParents[data.LegacyToken]; ok {
					l.rfpParents[data.LegacyToken].Mask = data.VoteDetailsMd.Params.Mask
					l.rfpParents[data.LegacyToken].Duration = data.VoteDetailsMd.Params.Duration
					l.rfpParents[data.LegacyToken].QuorumPercentage = data.VoteDetailsMd.Params.QuorumPercentage
					l.rfpParents[data.LegacyToken].PassPercentage = data.VoteDetailsMd.Params.PassPercentage
					l.rfpParents[data.LegacyToken].StartBlockHeight = data.VoteDetailsMd.StartBlockHeight
					l.rfpParents[data.LegacyToken].StartBlockHash = data.VoteDetailsMd.StartBlockHash
					l.rfpParents[data.LegacyToken].EndBlockHeight = data.VoteDetailsMd.EndBlockHeight
					l.rfpParents[data.LegacyToken].EligibleTickets = data.VoteDetailsMd.EligibleTickets
				} else {
					l.rfpParents[data.LegacyToken] = &startRunoffRecord{
						// Submissions:   Will be set when all records have been parsed
						// 				  and inserted to tstore.
						Mask:             data.VoteDetailsMd.Params.Mask,
						Duration:         data.VoteDetailsMd.Params.Duration,
						QuorumPercentage: data.VoteDetailsMd.Params.QuorumPercentage,
						PassPercentage:   data.VoteDetailsMd.Params.PassPercentage,
						StartBlockHeight: data.VoteDetailsMd.StartBlockHeight,
						StartBlockHash:   data.VoteDetailsMd.StartBlockHash,
						EndBlockHeight:   data.VoteDetailsMd.EndBlockHeight,
						EligibleTickets:  data.VoteDetailsMd.EligibleTickets,
					}
				}
				l.Unlock()
			}

			// Second, check if record is an RFP submission. If so, add it to
			// the submissions list of its parent, and add it to queue to be
			// parsed later on. No need to spin up a thread now, since RFP
			// submissions need to be parsed when their respective parent has
			// already been inserted.
			if data.VoteMd.LinkTo != "" {
				l.Lock()
				if _, ok := l.rfpParents[data.VoteMd.LinkTo]; ok {
					l.rfpParents[data.VoteMd.LinkTo].Submissions = append(
						l.rfpParents[data.VoteMd.LinkTo].Submissions, data.RecordMd.Token)
				} else {
					l.rfpParents[data.VoteMd.LinkTo] = &startRunoffRecord{
						Submissions: []string{data.RecordMd.Token},
					}
				}
				l.Unlock()

				queue = append(queue, &data)
				return nil
			}

			records = append(records, &data)

			return nil
		})
	if err != nil {
		return err
	}

	fmt.Printf("legacy: Importing %v records to tstore\n", len(records))

	var wg sync.WaitGroup
	for _, r := range records {
		// Spin thread to save record and their respective blobs to tstore.
		wg.Add(1)
		go func(data parsedData) error {
			defer wg.Done()

			// Save legacy record on tstore.
			err := l.saveRecordParsedData(data)
			if err != nil {
				panic(err)
			}

			return nil
		}(*r)
	}
	wg.Wait()

	fmt.Printf("legacy: Importing %v records on queue to tstore\n", len(queue))

	// Now, save RFP submissions records that are on queue.
	for _, record := range queue {
		wg.Add(1)
		go func(data parsedData) error {
			defer wg.Done()

			// Save legacy record on tstore.
			err := l.saveRecordParsedData(data)
			if err != nil {
				panic(err)
			}

			return nil
		}(*record)
	}
	wg.Wait()

	// Add the dataDescriptorStartRunoff blob for each RFP parent after
	// the submissions list has been built.
	l.RLock()
	for token, startRunoffRecord := range l.rfpParents {
		// Update submissions tokens with their new tlog tokens.
		var subs []string
		for _, s := range startRunoffRecord.Submissions {
			subs = append(subs, l.tokens[s])
		}
		startRunoffRecord.Submissions = subs

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

	return nil
}

// saveRecordData saves the parsed data onto tstore. It will try to:
//  1. First check if record is an RFP submission
//  2.
//  3. sabe blu
func (l *legacy) saveRecordParsedData(data parsedData) error {
	fmt.Printf("legacy: %v record being inserted to tstore\n",
		data.LegacyToken[:7])

	// Create a new tlog tree for the legacy record.
	newToken, err := l.tstore.RecordNew()
	if err != nil {
		return err
	}

	// Insert missing tokens data that is not inserted by the dump command.

	// Save legacy token to status change metadata.
	data.StatusChangeMd.Token = data.LegacyToken
	// Save new tstore token to record metadata.
	data.RecordMd.Token = hex.EncodeToString(newToken)
	// Save new tstore token to vote details params, if applicable.
	if data.VoteDetailsMd != nil {
		data.VoteDetailsMd.Params.Token = hex.EncodeToString(newToken)
	}
	// Save new tstore parent token to vote md and voteparams, if applicable.
	if data.VoteMd.LinkTo != "" {
		// Replace legacy parent token for new tlog token.
		l.RLock()
		data.VoteMd.LinkTo = l.tokens[data.VoteMd.LinkTo]
		l.RUnlock()
		data.VoteDetailsMd.Params.Parent = data.VoteMd.LinkTo
	}
	// Save new tstore token to vote md, if applicable.

	// Check to see if record is RFP parent. If so, update the RFP parents
	// cache with the new tlog token. This will make it easier to save the
	// start runoff blobs.
	l.Lock()
	_, ok := l.rfpParents[data.LegacyToken]
	if ok {
		l.rfpParents[hex.EncodeToString(newToken)] = l.rfpParents[data.LegacyToken]
		delete(l.rfpParents, data.LegacyToken)
	}
	l.Unlock()

	// Setup vote metadata file.
	if data.VoteMd.LinkBy != 0 || data.VoteMd.LinkTo != "" {
		b, err := json.Marshal(data.VoteMd)
		if err != nil {
			return err
		}
		vmd := &backend.File{
			Name:    "votemetadata.json",
			MIME:    mime.DetectMimeType(b),
			Digest:  hex.EncodeToString(util.Digest(b)),
			Payload: base64.StdEncoding.EncodeToString(b),
		}
		data.Files = append(data.Files, *vmd)
	}

	// Add status change metadata to metadata stream.
	b, err := json.Marshal(data.StatusChangeMd)
	if err != nil {
		return err
	}
	data.Metadata = append(data.Metadata, backend.MetadataStream{
		PluginID: pusermd.PluginID,
		StreamID: pusermd.StreamIDStatusChanges,
		Payload:  string(b),
	})

	// Save record to tstore.
	err = l.saveRecord(newToken, data.Files, data.Metadata, *data.RecordMd)
	if err != nil {
		return err
	}

	// Save authorize vote blob, if any.
	if data.AuthDetailsMd != nil {
		err = l.blobSaveAuthDetails(*data.AuthDetailsMd, newToken)
		if err != nil {
			return err
		}
	}

	// Save vote details blob, if any.
	if data.VoteDetailsMd != nil {
		err = l.blobSaveVoteDetails(*data.VoteDetailsMd, newToken)
		if err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	// Spin routine for saving comment blobs.
	if data.Comments != nil {
		wg.Add(1)
		go func() error {
			defer wg.Done()
			err = l.saveCommentsBlobs(*data.Comments, newToken)
			if err != nil {
				panic(err)
			}
			return nil
		}()
	}
	// Spin routine for saving vote blobs.
	if data.Votes != nil {
		wg.Add(1)
		go func() error {
			defer wg.Done()
			err = l.saveVotesBlobs(data.Votes, newToken)
			if err != nil {
				panic(err)
			}
			return nil
		}()
	}
	wg.Wait()

	// Save legacy token to new token mapping in cache.
	l.Lock()
	l.tokens[data.LegacyToken] = hex.EncodeToString(newToken)
	l.Unlock()

	fmt.Printf("legacy: %v record inserted to tstore, new token: %v\n",
		data.LegacyToken[:7], hex.EncodeToString(newToken))

	return nil
}

// recordSave saves a record to tstore.
func (l *legacy) saveRecord(newToken []byte, files []backend.File, metadata []backend.MetadataStream, recordmd backend.RecordMetadata) error {
	// Verify metadata streams and files data.
	err := metadataStreamsVerify(metadata)
	if err != nil {
		return err
	}
	err = filesVerify(files, nil)
	if err != nil {
		return err
	}

	// Check if record status is public. If so, we need to first save it as
	// unreviewed, and after save it as public, so we can bypass the RecordSave
	// function validations.
	isPublic := false
	if recordmd.Status == backend.StatusPublic {
		isPublic = true
		recordmd.Status = backend.StatusUnreviewed
	}

	err = l.tstore.RecordSave(newToken, recordmd, metadata, files)
	if err != nil {
		return err
	}

	// If it's public, update from unreviewed to public status.
	if isPublic {
		recordmd.Status = backend.StatusPublic
		recordmd.Iteration = 2
		err = l.tstore.RecordSave(newToken, recordmd, metadata, files)
		if err != nil {
			return err
		}
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
