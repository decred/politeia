package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/mdstream"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backendv1 "github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backendv2"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	pusermd "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
	"github.com/subosito/gozaru"
)

// recordSave saves a record to tstore.
func (l *legacyImport) recordSave(newToken []byte, files []backend.File, metadata []backend.MetadataStream, recordmd backend.RecordMetadata) error {
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

// fetchUserByPubKey makes a call to the politeia API requesting the user
// with the provided public key.
func (l *legacyImport) fetchUserByPubKey(pubkey string) (*user, error) {
	url := "https://proposals.decred.org/api/v1/users?publickey=" + pubkey
	r, err := l.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ur usersReply
	err = json.Unmarshal(body, &ur)
	if err != nil {
		return nil, err
	}

	if len(ur.Users) == 0 {
		return nil, fmt.Errorf("no user found for pubkey %v", pubkey)
	}

	return &ur.Users[0], nil
}

// convertRecordMetadata reads the recordmetadata.json from the gitbe record
// and converts it to a RecordMetadata for the tlogbe.
func convertRecordMetadata(path string) (*backendv2.RecordMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mdv1 *backendv1.RecordMetadata
	err = json.Unmarshal(b, &mdv1)
	if err != nil {
		return nil, err
	}

	var mdv2 backendv2.RecordMetadata
	mdv2.Token = mdv1.Token
	mdv2.State = backend.StateVetted
	mdv2.Merkle = mdv1.Merkle
	mdv2.Timestamp = mdv1.Timestamp
	mdv2.Version = 1
	mdv2.Iteration = 1

	// Convert backend v1 status to v2.
	switch {
	case mdv1.Status == backendv1.MDStatusInvalid:
		mdv2.Status = backendv2.StatusInvalid
	case mdv1.Status == backendv1.MDStatusUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusVetted:
		mdv2.Status = backendv2.StatusPublic
	case mdv1.Status == backendv1.MDStatusCensored:
		mdv2.Status = backendv2.StatusCensored
	case mdv1.Status == backendv1.MDStatusIterationUnvetted:
		mdv2.Status = backendv2.StatusUnreviewed
	case mdv1.Status == backendv1.MDStatusArchived:
		mdv2.Status = backendv2.StatusArchived
	default:
		return nil, err
	}

	return &mdv2, nil
}

// convertStatusChangeMetadata converts the 02.metadata.txt status change md
// from legacy git records.
func convertStatusChangeMetadata(path string) (*usermd.StatusChangeMetadata, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var (
		rsc     mdstream.RecordStatusChangeV2
		streams []mdstream.RecordStatusChangeV2
	)
	err = json.Unmarshal(b, &rsc)
	if err != nil {
		// Record has 02.metadata.txt containing nested status changes.
		split := strings.Split(string(b), "}")
		for _, v := range split {
			if v == "" {
				continue
			}
			err = json.Unmarshal([]byte(v+"}"), &rsc)
			if err != nil {
				return nil, err
			}
			streams = append(streams, rsc)
		}
	} else {
		streams = append(streams, rsc)
	}

	// Return most recent status change md.
	latest := streams[len(streams)-1]

	// Many proposals do not have the signature on the 02.metadata.txt
	// status change data.
	return &pusermd.StatusChangeMetadata{
		Version:   uint32(latest.Version),
		Status:    uint32(latest.NewStatus),
		Reason:    latest.StatusChangeMessage,
		PublicKey: latest.AdminPubKey,
		Signature: latest.Signature,
		Timestamp: latest.Timestamp,
	}, nil
}

// convertUserMetadata converts the 00.metadata.txt file which contains the
// ProposalGeneralV1 metadata structure previously used on legacy git records.
func (l *legacyImport) convertUserMetadata(path string) (*usermd.UserMetadata, string, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var pgv1 proposalGeneralV1
	err = json.Unmarshal(b, &pgv1)
	if err != nil {
		return nil, "", err
	}

	usr, err := l.fetchUserByPubKey(pgv1.PublicKey)
	if err != nil {
		return nil, "", err
	}

	// Check if userid flag is set, used for testing.
	id := usr.ID
	if *userid != "" {
		id = *userid
	}

	// If userid/publickey is data from a user that is not registered in the
	// local userdb this tool is using, then recordSave will error out.
	return &pusermd.UserMetadata{
		UserID:    id,
		PublicKey: pgv1.PublicKey,

		// The signature for this struct is not coherent on tlog due to
		// significant data changes.

		// Signature: pgv1.Signature,
	}, pgv1.Name, nil
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
