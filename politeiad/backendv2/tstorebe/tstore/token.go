// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/binary"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/util"
)

const (
	// ShortTokenKeyPrefix is the key prefix for the cached short token entry.
	// Each record token will have a short token to full length token mapping
	// cached in the key-value store.
	//
	// The short token is the first n characters of the hex encoded record token,
	// where n is defined by the short token length politeiad setting. Record
	// lookups using short tokens are allowed. The cached short tokens are used
	// to prevent collisions when creating new tokens and to facilitate lookups
	// using the short token.
	shortTokenKeyPrefix = "pd-shorttoken-"
)

// cacheShortToken caches a short token entry in the key-value store for the
// provided full length token.
func (t *Tstore) cacheShortToken(fullToken []byte) error {
	if !tokenIsFullLength(fullToken) {
		return fmt.Errorf("token is not full length")
	}
	key, err := shortTokenKey(fullToken)
	if err != nil {
		return err
	}
	err = t.store.Put(map[string][]byte{key: fullToken}, false)
	if err != nil {
		return err
	}

	log.Debugf("Short token cached for %x", fullToken)

	return nil
}

// shortTokenIsUnique returns whether the shortend version of the provided
// token is unique. The provided token can be either a full length token or a
// shortened token. It's possible for two different full length tokens to have
// the same shortened version. These types of collisions should be checked for
// and prevented when creating new tokens.
func (t *Tstore) shortTokenIsUnique(token []byte) (bool, error) {
	key, err := shortTokenKey(token)
	if err != nil {
		return false, err
	}
	blobs, err := t.store.Get([]string{key})
	if err != nil {
		return false, err
	}
	_, ok := blobs[key]
	if ok {
		// An existing entry was found for this
		// shortened token. It is not unique.
		return false, nil
	}

	// This short token is unique
	return true, nil
}

// fullLengthToken returns the full length token given the short token. A
// ErrRecordNotFound error is returned if a record does not exist for the
// provided token.
func (t *Tstore) fullLengthToken(shortToken []byte) ([]byte, error) {
	if tokenIsFullLength(shortToken) {
		// Token is already full length. Nothing else to do.
		return shortToken, nil
	}

	// Get the cached short token entry
	key, err := shortTokenKey(shortToken)
	if err != nil {
		return nil, err
	}
	blobs, err := t.store.Get([]string{key})
	if err != nil {
		return nil, err
	}
	fullToken, ok := blobs[key]
	if !ok {
		// A record does not exist for the provided short token.
		return nil, backend.ErrRecordNotFound
	}

	return fullToken, nil
}

// shortTokenKey accepts both full length tokens or short tokens and returns
// the key-value store key for the short token cache entry.
func shortTokenKey(token []byte) (string, error) {
	shortToken, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	return shortTokenKeyPrefix + shortToken, nil
}

// treeIDFromToken returns the tlog tree ID for the given record token.
func treeIDFromToken(token []byte) int64 {
	return int64(binary.LittleEndian.Uint64(token))
}

// tokenFromTreeID returns the record token for a tlog tree.
func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

// tokenIsFullLength returns whether the token is a full length token.
func tokenIsFullLength(token []byte) bool {
	return util.TokenIsFullLength(util.TokenTypeTstore, token)
}

// tokenDecode takes a hex encoded token and returns the decode byte slice.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecodeAnyLength(util.TokenTypeTstore, token)
}
