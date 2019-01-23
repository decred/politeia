// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
)

// verifyRecordVersion checks the provided record version against the current
// database implementation version.
func verifyRecordVersion(recordVersion uint32) error {
	if recordVersion != DatabaseVersion {
		return ErrWrongRecordVersion
	}
	return nil
}

// verifyRecordType verifies the provided record type against the expected type
func verifyRecordType(recordType, expectedType RecordTypeT) error {
	if recordType != expectedType {
		return ErrWrongRecordType
	}
	return nil
}

// EncodeVersion encodes Version into a JSON byte slice. It also adds the
// record type and version before encoding.
func EncodeVersion(version Version) ([]byte, error) {
	// Make sure it has record type and version specified
	version.RecordType = RecordTypeVersion
	version.RecordVersion = DatabaseVersion

	b, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeVersion decodes a JSON byte slice into a Version.
func DecodeVersion(payload []byte) (*Version, error) {
	var version Version

	err := json.Unmarshal(payload, &version)
	if err != nil {
		return nil, err
	}

	err = verifyRecordVersion(version.RecordVersion)
	if err != nil {
		return nil, err
	}

	err = verifyRecordType(version.RecordType, RecordTypeVersion)
	if err != nil {
		return nil, err
	}

	return &version, nil
}

// EncodeUser encodes User into a JSON byte slice. It also adds the
// record type and record version before encoding.
func EncodeUser(u User) ([]byte, error) {
	// Make sure it  has record type and version specified
	u.RecordType = RecordTypeUser
	u.RecordVersion = DatabaseVersion

	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// EncodeLastPaywallAddressIndex encodes User into a JSON byte slice.
// It also adds the record type and version before encoding.
func EncodeLastPaywallAddressIndex(lp LastPaywallAddressIndex) ([]byte, error) {
	// Make sure it has record type and version specified
	lp.RecordType = RecordTypeLastPaywallAddrIdx
	lp.RecordVersion = DatabaseVersion

	b, err := json.Marshal(lp)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeLastPaywallAddressIndex decodes a JSON byte slice into a
// LastPaywallAddressIndex.
func DecodeLastPaywallAddressIndex(payload []byte) (*LastPaywallAddressIndex, error) {
	var lp LastPaywallAddressIndex

	err := json.Unmarshal(payload, &lp)
	if err != nil {
		return nil, err
	}

	err = verifyRecordVersion(lp.RecordVersion)
	if err != nil {
		return nil, err
	}

	err = verifyRecordType(lp.RecordType, RecordTypeLastPaywallAddrIdx)
	if err != nil {
		return nil, err
	}

	return &lp, nil
}

// DecodeUser decodes a JSON byte slice into a User.
func DecodeUser(payload []byte) (*User, error) {
	var u User

	err := json.Unmarshal(payload, &u)
	if err != nil {
		return nil, err
	}

	err = verifyRecordVersion(u.RecordVersion)
	if err != nil {
		return nil, err
	}

	err = verifyRecordType(u.RecordType, RecordTypeUser)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// EncodeEncryptionKey encodes EncryptionKey into a JSON byte slice.
func EncodeEncryptionKey(ek EncryptionKey) ([]byte, error) {
	k, err := json.Marshal(ek)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// DecodeEncryptionKey decodes a JSON byte slice into EncryptionKey.
func DecodeEncryptionKey(payload []byte) (*EncryptionKey, error) {
	var ek EncryptionKey

	err := json.Unmarshal(payload, &ek)
	if err != nil {
		return nil, err
	}

	return &ek, nil
}

// EncodeSnapshot encodes a Snapshot into a JSON byte slice.
func EncodeSnapshot(s Snapshot) ([]byte, error) {
	p, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// DecodeSnapshot decodes a JSON byte slice into Snapshot.
func DecodeSnapshot(payload []byte) (*Snapshot, error) {
	var ss Snapshot

	err := json.Unmarshal(payload, &ss)
	if err != nil {
		return nil, err
	}

	return &ss, nil
}
