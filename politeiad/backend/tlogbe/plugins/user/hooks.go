// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/user"
	pdutil "github.com/decred/politeia/politeiad/util"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s user.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = user.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = user.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     user.PluginID,
		ErrorCode:    int(s),
		ErrorContext: e.ErrorContext,
	}
}

// userMetadataDecode decodes and returns the UserMetadata from the provided
// backend metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(metadata []backend.MetadataStream) (*user.UserMetadata, error) {
	var userMD *user.UserMetadata
	for _, v := range metadata {
		if v.ID == user.MDStreamIDUserMetadata {
			var um user.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
			userMD = &um
			break
		}
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
			PluginID:  user.PluginID,
			ErrorCode: int(user.ErrorCodeUserMetadataNotFound),
		}
	}

	// Verify user ID
	_, err = uuid.Parse(um.UserID)
	if err != nil {
		return backend.PluginError{
			PluginID:  user.PluginID,
			ErrorCode: int(user.ErrorCodeUserIDInvalid),
		}
	}

	// Verify signature
	m, err := pdutil.MerkleRoot(files)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(m[:])
	err = util.VerifySignature(um.Signature, um.PublicKey, msg)
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
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeUserIDInvalid),
			ErrorContext: e,
		}

	case u.PublicKey != c.PublicKey:
		e := fmt.Sprintf("public key cannot change: got %v, want %v",
			u.PublicKey, c.PublicKey)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodePublicKeyInvalid),
			ErrorContext: e,
		}

	case c.Signature != c.Signature:
		e := fmt.Sprintf("signature cannot change: got %v, want %v",
			u.Signature, c.Signature)
		return backend.PluginError{
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeSignatureInvalid),
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
			PluginID:     user.PluginID,
			ErrorCode:    int(user.ErrorCodeUserIDInvalid),
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

func (p *userPlugin) hookSetRecordStatusPre(payload string) error {
	var srs plugins.HookSetRecordStatus
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return err
	}

	// User metadata should not change on status changes
	return userMetadataPreventUpdates(srs.Current.Metadata, srs.Metadata)
}
