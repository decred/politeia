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
		ErrorCode:    int(s),
		ErrorContext: e.ErrorContext,
	}
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
			ErrorCode: int(usermd.ErrorCodeUserMetadataNotFound),
		}
	}

	// Verify user ID
	_, err = uuid.Parse(um.UserID)
	if err != nil {
		return backend.PluginError{
			PluginID:  usermd.PluginID,
			ErrorCode: int(usermd.ErrorCodeUserIDInvalid),
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
		e := fmt.Sprintf("user id cannot change: got %v, want %v",
			u.UserID, c.UserID)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeUserIDInvalid),
			ErrorContext: e,
		}

	case u.PublicKey != c.PublicKey:
		e := fmt.Sprintf("public key cannot change: got %v, want %v",
			u.PublicKey, c.PublicKey)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodePublicKeyInvalid),
			ErrorContext: e,
		}

	case c.Signature != c.Signature:
		e := fmt.Sprintf("signature cannot change: got %v, want %v",
			u.Signature, c.Signature)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeSignatureInvalid),
			ErrorContext: e,
		}
	}

	return nil
}

func (p *userPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	return userMetadataVerify(nr.Metadata, nr.Files)
}

func (p *userPlugin) hookNewRecordPost(payload string) error {
	var nr plugins.HookNewRecordPost
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	// Decode user metadata
	um, err := userMetadataDecode(nr.Metadata)
	if err != nil {
		return err
	}

	// Add token to the user cache
	err = p.userCacheAddToken(um.UserID, nr.RecordMetadata.Token)
	if err != nil {
		return err
	}

	return nil
}

func (p *userPlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify user metadata
	err = userMetadataVerify(er.Metadata, er.Files)
	if err != nil {
		return err
	}

	// Verify user ID has not changed
	um, err := userMetadataDecode(er.Metadata)
	if err != nil {
		return err
	}
	umCurr, err := userMetadataDecode(er.Current.Metadata)
	if err != nil {
		return err
	}
	if um.UserID != umCurr.UserID {
		e := fmt.Sprintf("user id cannot change: got %v, want %v",
			um.UserID, umCurr.UserID)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeUserIDInvalid),
			ErrorContext: e,
		}
	}

	return nil
}

func (p *userPlugin) hookEditMetadataPre(payload string) error {
	var em plugins.HookEditMetadata
	err := json.Unmarshal([]byte(payload), &em)
	if err != nil {
		return err
	}

	// User metadata should not change on metadata updates
	return userMetadataPreventUpdates(em.Current.Metadata, em.Metadata)
}

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
			ErrorCode: int(usermd.ErrorCodeStatusChangeMetadataNotFound),
		}
	}
	scm := statusChanges[len(statusChanges)-1]

	// Verify token matches
	if scm.Token != rm.Token {
		e := fmt.Sprintf("status change token does not match record "+
			"metadata token: got %v, want %v", scm.Token, rm.Token)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify status matches
	if scm.Status != uint32(rm.Status) {
		e := fmt.Sprintf("status from metadata does not match status from "+
			"record metadata: got %v, want %v", scm.Status, rm.Status)
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeStatusInvalid),
			ErrorContext: e,
		}
	}

	// Verify reason was included on required status changes
	_, ok := statusReasonRequired[rm.Status]
	if ok && scm.Reason == "" {
		return backend.PluginError{
			PluginID:     usermd.PluginID,
			ErrorCode:    int(usermd.ErrorCodeReasonInvalid),
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

func (p *userPlugin) hookSetRecordStatusPre(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// User metadata should not change on status changes
	err = userMetadataPreventUpdates(srs.Current.Metadata, srs.Metadata)
	if err != nil {
		return err
	}

	// Verify status change metadata
	err = statusChangeMetadataVerify(srs.RecordMetadata, srs.Metadata)
	if err != nil {
		return err
	}

	return nil
}

func (p *userPlugin) hookSetRecordStatusPost(treeID int64, payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// When a record is made public it is moved from the unvetted to
	// the vetted tstore instance. The token must be removed from the
	// unvetted user cache and added to the vetted user cache.
	if srs.RecordMetadata.Status == backend.StatusPublic {
		// Decode user metadata
		um, err := userMetadataDecode(srs.Metadata)
		if err != nil {
			return err
		}

		// When a record is moved to vetted the plugin hooks are executed
		// on both the unvetted and vetted tstore instances. The token
		// needs to be removed from the unvetted tstore user cache and
		// added to the vetted tstore user cache. We can determine this
		// by checking if the record exists. The unvetted instance will
		// return false.
		if p.tstore.RecordExists(treeID) {
			// This is the vetted tstore. Add token to the user cache.
			err = p.userCacheAddToken(um.UserID, srs.RecordMetadata.Token)
			if err != nil {
				return err
			}
		} else {
			// This is the unvetted tstore. Del token from user cache.
			err = p.userCacheDelToken(um.UserID, srs.RecordMetadata.Token)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
