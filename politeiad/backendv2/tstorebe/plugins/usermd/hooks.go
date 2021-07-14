// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// hookRecordNewPre adds plugin specific validation onto the tstore backend
// RecordNew method.
func (p *usermdPlugin) hookRecordNewPre(payload string) error {
	var rn plugins.RecordNew
	err := json.Unmarshal([]byte(payload), &rn)
	if err != nil {
		return err
	}

	return userMetadataVerify(rn.Metadata, rn.Files)
}

// hookRecordNewPre caches plugin data from the tstore backend RecordNew
// method.
func (p *usermdPlugin) hookRecordNewPost(payload string) error {
	var rn plugins.RecordNew
	err := json.Unmarshal([]byte(payload), &rn)
	if err != nil {
		return err
	}

	// Decode user metadata
	um, err := userMetadataDecode(rn.Metadata)
	if err != nil {
		return err
	}

	// Add token to the user cache
	err = p.userCacheAddToken(um.UserID, rn.RecordMetadata.State,
		rn.RecordMetadata.Token)
	if err != nil {
		return err
	}

	return nil
}

// hookRecordEditPre adds plugin specific validation onto the tstore backend
// RecordEdit method.
func (p *usermdPlugin) hookRecordEditPre(payload string) error {
	var re plugins.RecordEdit
	err := json.Unmarshal([]byte(payload), &re)
	if err != nil {
		return err
	}

	// Verify user metadata
	err = userMetadataVerify(re.Metadata, re.Files)
	if err != nil {
		return err
	}

	// Verify user ID has not changed
	um, err := userMetadataDecode(re.Metadata)
	if err != nil {
		return err
	}
	umCurr, err := userMetadataDecode(re.Record.Metadata)
	if err != nil {
		return err
	}
	if um.UserID != umCurr.UserID {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeUserIDInvalid),
			ErrorContext: fmt.Sprintf("user id cannot change: got %v, want %v",
				um.UserID, umCurr.UserID),
		}
	}

	return nil
}

// hookRecordEditMetadataPre adds plugin specific validation onto the tstore
// backend RecordEditMetadata method.
func (p *usermdPlugin) hookRecordEditMetadataPre(payload string) error {
	var rem plugins.RecordEditMetadata
	err := json.Unmarshal([]byte(payload), &rem)
	if err != nil {
		return err
	}

	// User metadata should not change on metadata updates
	return userMetadataPreventUpdates(rem.Record.Metadata, rem.Metadata)
}

// hookRecordSetStatusPre adds plugin specific validation onto the tstore
// backend RecordSetStatus method.
func (p *usermdPlugin) hookRecordSetStatusPre(payload string) error {
	var rss plugins.RecordSetStatus
	err := json.Unmarshal([]byte(payload), &rss)
	if err != nil {
		return err
	}

	// User metadata should not change on status changes
	err = userMetadataPreventUpdates(rss.Record.Metadata, rss.Metadata)
	if err != nil {
		return err
	}

	// Verify status change metadata
	err = statusChangeMetadataVerify(rss.RecordMetadata, rss.Metadata)
	if err != nil {
		return err
	}

	return nil
}

// hookRecordSetStatusPost caches plugin data from the tstore backend
// RecordSetStatus method.
func (p *usermdPlugin) hookRecordSetStatusPost(payload string) error {
	var rss plugins.RecordSetStatus
	err := json.Unmarshal([]byte(payload), &rss)
	if err != nil {
		return err
	}
	rm := rss.RecordMetadata

	// When a record is made public the token must be moved from the
	// unvetted list to the vetted list in the user cache.
	if rm.Status == backend.StatusPublic {
		um, err := userMetadataDecode(rss.Metadata)
		if err != nil {
			return err
		}
		err = p.userCacheMoveTokenToVetted(um.UserID, rm.Token)
		if err != nil {
			return err
		}
	}

	return nil
}

// userMetadataDecode decodes and returns the UserMetadata from the provided
// backend metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(metadata []backend.MetadataStream) (*usermd.UserMetadata, error) {
	var userMD *usermd.UserMetadata
	for _, v := range metadata {
		if v.PluginID != usermd.PluginID ||
			v.StreamID != usermd.StreamIDUserMetadata {
			// Not the mdstream we're looking for
			continue
		}
		var um usermd.UserMetadata
		err := json.Unmarshal([]byte(v.Payload), &um)
		if err != nil {
			return nil, err
		}
		userMD = &um
		break
	}
	return userMD, nil
}

// userMetadataVerify parses a UserMetadata from the metadata streams and
// verifies its contents are valid.
func userMetadataVerify(metadata []backend.MetadataStream, files []backend.File) error {
	// Decode user metadata
	um, err := userMetadataDecode(metadata)
	if err != nil {
		return err
	}
	if um == nil {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeUserMetadataNotFound),
		}
	}

	// Verify user ID
	_, err = uuid.Parse(um.UserID)
	if err != nil {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeUserIDInvalid),
		}
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
		return convertSignatureError(err)
	}

	return nil
}

// userMetadataPreventUpdates errors if the UserMetadata is being updated.
func userMetadataPreventUpdates(current, update []backend.MetadataStream) error {
	// Decode user metadata
	c, err := userMetadataDecode(current)
	if err != nil {
		return err
	}
	u, err := userMetadataDecode(update)
	if err != nil {
		return err
	}

	// Verify user metadata has not changed
	switch {
	case u.UserID != c.UserID:
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeUserIDInvalid),
			ErrorContext: fmt.Sprintf("user id cannot change: got %v, want %v",
				u.UserID, c.UserID),
		}

	case u.PublicKey != c.PublicKey:
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodePublicKeyInvalid),
			ErrorContext: fmt.Sprintf("public key cannot change: got %v, want %v",
				u.PublicKey, c.PublicKey),
		}

	case c.Signature != c.Signature:
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeSignatureInvalid),
			ErrorContext: fmt.Sprintf("signature cannot change: got %v, want %v",
				u.Signature, c.Signature),
		}
	}

	return nil
}

// statusChangesDecode decodes and returns the StatusChangeMetadata from the
// metadata streams if one is present.
func statusChangesDecode(metadata []backend.MetadataStream) ([]usermd.StatusChangeMetadata, error) {
	statuses := make([]usermd.StatusChangeMetadata, 0, 16)
	for _, v := range metadata {
		if v.PluginID != usermd.PluginID ||
			v.StreamID != usermd.StreamIDStatusChanges {
			// Not the mdstream we're looking for
			continue
		}
		d := json.NewDecoder(strings.NewReader(v.Payload))
		for {
			var sc usermd.StatusChangeMetadata
			err := d.Decode(&sc)
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, err
			}
			statuses = append(statuses, sc)
		}
		break
	}
	return statuses, nil
}

var (
	// statusReasonRequired contains the list of record statuses that
	// require an accompanying reason to be given in the status change.
	statusReasonRequired = map[backend.StatusT]struct{}{
		backend.StatusCensored: {},
		backend.StatusArchived: {},
	}
)

// statusChangeMetadataVerify parses the status change metadata from the
// metadata streams and verifies that its contents are valid.
func statusChangeMetadataVerify(rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Decode status change metadata
	statusChanges, err := statusChangesDecode(metadata)
	if err != nil {
		return err
	}

	// Verify that status change metadata is present
	if len(statusChanges) == 0 {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeStatusChangeMetadataNotFound),
		}
	}
	scm := statusChanges[len(statusChanges)-1]

	// Verify token matches
	if scm.Token != rm.Token {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeTokenInvalid),
			ErrorContext: fmt.Sprintf("status change token does not match "+
				"record metadata token: got %v, want %v", scm.Token, rm.Token),
		}
	}

	// Verify status matches
	if scm.Status != uint32(rm.Status) {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: uint32(usermd.ErrorCodeStatusInvalid),
			ErrorContext: fmt.Sprintf("status from metadata does not "+
				"match status from record metadata: got %v, want %v",
				scm.Status, rm.Status),
		}
	}

	// Verify reason was included on required status changes
	_, ok := statusReasonRequired[rm.Status]
	if ok && scm.Reason == "" {
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    uint32(usermd.ErrorCodeReasonMissing),
			ErrorContext: "a reason must be given for this status change",
		}
	}

	// Verify signature
	status := strconv.FormatUint(uint64(scm.Status), 10)
	version := strconv.FormatUint(uint64(scm.Version), 10)
	msg := scm.Token + version + status + scm.Reason
	err = util.VerifySignature(scm.Signature, scm.PublicKey, msg)
	if err != nil {
		return convertSignatureError(err)
	}

	return nil
}

func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s usermd.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = usermd.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = usermd.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     usermd.PluginID,
		ErrorCode:    uint32(s),
		ErrorContext: e.ErrorContext,
	}
}
