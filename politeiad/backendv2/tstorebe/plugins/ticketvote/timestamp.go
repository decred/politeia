// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// voteTimestampKey is the key for a ticket vote timestamp entry in the
	// key-value store cache.
	voteTimestampKey = "timestamp-vote-{shorttoken}-{page}-{index}"

	// authTimestampKey is the key for a vote auth timestamp entry in the
	// key-value store cache.
	authTimestampKey = "timestamp-auth-{shorttoken}-{index}"

	// detailsTimestampKey is the key for a vote details timestamp entry in the
	// key-value store cache.
	detailsTimestampKey = "timestamp-details-{shorttoken}"
)

// cacheFinalVoteTimestamps accepts a slice of vote timestamps, it collects the
// final timestamps then stores them in the key-value store.
func (p *ticketVotePlugin) cacheFinalVoteTimestamps(token []byte, ts []ticketvote.Timestamp, page uint32) error {
	// Collect final timestamps
	fts := make([]ticketvote.Timestamp, 0, len(ts))
	for _, t := range ts {
		if timestampIsFinal(t) {
			fts = append(fts, t)
		}
	}

	// Store final timestamp
	err := p.saveVoteTimestamps(token, fts, page)
	if err != nil {
		return err
	}

	log.Debugf("Cached final vote timestamps of %v/%v",
		len(fts), len(ts))
	return nil
}

// saveVoteTimestamps saves a slice of vote timestamps to the key-value cache.
func (p *ticketVotePlugin) saveVoteTimestamps(token []byte, ts []ticketvote.Timestamp, page uint32) error {
	// Setup the blob entries
	blobs := make(map[string][]byte, len(ts))
	keys := make([]string, 0, len(ts))
	for i, v := range ts {
		k, err := getVoteTimestampKey(token, page, uint32(i))
		if err != nil {
			return err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		blobs[k] = b
		keys = append(keys, k)
	}

	// Delete exisiting digests
	err := p.tstore.CacheDel(keys)
	if err != nil {
		return err
	}

	// Save the blob entries
	return p.tstore.CachePut(blobs, false)
}

// cachedVoteTimestamps returns cached vote timestamps if they exist. It
// accepts the requested page as the vote timestamps request is paginated and
// both the page number and the vote index are part of the vote's cache key.
func (p *ticketVotePlugin) cachedVoteTimestamps(token []byte, page, pageSize uint32) ([]ticketvote.Timestamp, error) {
	// Setup the timestamp keys
	keys := make([]string, 0, pageSize)
	for i := uint32(0); i < pageSize; i++ {
		key, err := getVoteTimestampKey(token, page, i)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	// Get the timestamp blob entries
	blobs, err := p.tstore.CacheGet(keys)
	if err != nil {
		return nil, err
	}

	// Decode the timestamps
	ts := make([]ticketvote.Timestamp, len(blobs))
	for k, v := range blobs {
		var t ticketvote.Timestamp
		err := json.Unmarshal(v, &t)
		if err != nil {
			return nil, err
		}
		idx, err := parseVoteTimestampKey(k)
		if err != nil {
			return nil, err
		}
		ts[idx] = t
	}

	log.Debugf("Retrieved %v cached final vote timestamps", len(ts))
	return ts, nil
}

// getVoteTimestampVoteKey returns the key for a vote timestamp in the
// key-value store cache.
func getVoteTimestampKey(token []byte, page, index uint32) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	pageStr := strconv.FormatUint(uint64(page), 10)
	indexStr := strconv.FormatUint(uint64(index), 10)
	key := strings.Replace(voteTimestampKey, "{shorttoken}", t, 1)
	key = strings.Replace(key, "{page}", pageStr, 1)
	key = strings.Replace(key, "{index}", indexStr, 1)
	return key, nil
}

// parseVoteTimestampKey parses the item index from a vote timestamp key.
func parseVoteTimestampKey(key string) (uint32, error) {
	s := strings.Split(key, "-")
	if len(s) != 5 {
		return 0, errors.Errorf("invalid vote timestamp key")
	}
	index, err := strconv.ParseUint(s[4], 10, 64)
	if err != nil {
		return 0, err
	}
	return uint32(index), nil
}

// cacheFinalVoteTimestamps accepts a slice of auth timestamps, it collects the
// final timestamps then stores them in the key-value store.
func (p *ticketVotePlugin) cacheFinalAuthTimestamps(token []byte, ts []ticketvote.Timestamp) error {
	// Collect final timestamps
	fts := make([]ticketvote.Timestamp, 0, len(ts))
	for _, t := range ts {
		if timestampIsFinal(t) {
			fts = append(fts, t)
		}
	}

	// Store final timestamp
	err := p.saveAuthTimestamps(token, fts)
	if err != nil {
		return err
	}

	log.Debugf("Cached final auth timestamps of %v/%v",
		len(fts), len(ts))
	return nil
}

// saveAuthTimestamps saves a slice of vote timestamps to the key-value cache.
func (p *ticketVotePlugin) saveAuthTimestamps(token []byte, ts []ticketvote.Timestamp) error {
	// Setup the blob entries
	blobs := make(map[string][]byte, len(ts))
	keys := make([]string, 0, len(ts))
	for i, v := range ts {
		k, err := getAuthTimestampKey(token, uint32(i))
		if err != nil {
			return err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		blobs[k] = b
		keys = append(keys, k)
	}

	// Delete exisiting digests
	err := p.tstore.CacheDel(keys)
	if err != nil {
		return err
	}

	// Save the blob entries
	return p.tstore.CachePut(blobs, false)
}

// cachedAuthTimestamps returns cached auth timestamps if they exist.
func (p *ticketVotePlugin) cachedAuthTimestamps(token []byte) ([]ticketvote.Timestamp, error) {
	// Setup the timestamp keys
	keys := make([]string, 0, 256)
	for i := uint32(0); i < 256; i++ {
		key, err := getAuthTimestampKey(token, i)
		if err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	// Get the timestamp blob entries
	blobs, err := p.tstore.CacheGet(keys)
	if err != nil {
		return nil, err
	}

	// Decode the timestamps
	ts := make([]ticketvote.Timestamp, len(blobs))
	for k, v := range blobs {
		var t ticketvote.Timestamp
		err := json.Unmarshal(v, &t)
		if err != nil {
			return nil, err
		}
		idx, err := parseAuthTimestampKey(k)
		if err != nil {
			return nil, err
		}
		ts[idx] = t
	}

	log.Debugf("Retrieved %v cached final auth timestamps", len(ts))
	return ts, nil
}

// getAuthTimestampVoteKey returns the key for a auth timestamp in the
// key-value store cache.
func getAuthTimestampKey(token []byte, index uint32) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	indexStr := strconv.FormatUint(uint64(index), 10)
	key := strings.Replace(authTimestampKey, "{shorttoken}", t, 1)
	key = strings.Replace(key, "{index}", indexStr, 1)
	return key, nil
}

// parseAuthTimestampKey parses the item index from a auth timestamp key.
func parseAuthTimestampKey(key string) (uint32, error) {
	s := strings.Split(key, "-")
	if len(s) != 4 {
		return 0, errors.Errorf("invalid auth timestamp key")
	}
	index, err := strconv.ParseUint(s[3], 10, 64)
	if err != nil {
		return 0, err
	}
	return uint32(index), nil
}

// cacheFinalDetailsTimestamp accepts a vote details timestamp, if the given
// vote details timestamp is final it stores in the key-value store.
func (p *ticketVotePlugin) cacheFinalDetailsTimestamp(token []byte, t ticketvote.Timestamp) error {
	// Check whether given timestamp is final
	if timestampIsFinal(t) {
		// Store final timestamp in cache
		err := p.saveDetailsTimestamp(token, t)
		if err != nil {
			return err
		}

		log.Debugf("Cached final vote details timestamp of %v",
			hex.EncodeToString(token))
	}

	return nil
}

// saveDetailsTimestamp saves a slice of vote timestamps to the key-value cache.
func (p *ticketVotePlugin) saveDetailsTimestamp(token []byte, t ticketvote.Timestamp) error {
	// Setup the blob entry
	blobs := make(map[string][]byte, 1)
	k, err := getDetailsTimestampKey(token)
	if err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	blobs[k] = b

	// Delete exisiting digests
	err = p.tstore.CacheDel([]string{k})
	if err != nil {
		return err
	}

	// Save the blob entries
	return p.tstore.CachePut(blobs, false)
}

// cachedDetailsTimestamp returns cached vote details timestamp if one exist.
func (p *ticketVotePlugin) cachedDetailsTimestamp(token []byte) (*ticketvote.Timestamp, error) {
	// Setup the timestamp key
	key, err := getDetailsTimestampKey(token)
	if err != nil {
		return nil, err
	}

	// Get the timestamp blob entry
	blobs, err := p.tstore.CacheGet([]string{key})
	if err != nil {
		return nil, err
	}

	// There should never be more than a one cached vote details
	if len(blobs) > 1 {
		return nil, fmt.Errorf("invalid vote details count: "+
			"got %v, want 1", len(blobs))
	}

	// Decode the timestamp if one found
	if len(blobs) > 0 {
		var t ticketvote.Timestamp
		err = json.Unmarshal(blobs[key], &t)
		if err != nil {
			return nil, err
		}

		log.Debugf("Retrieved cached vote details for %v",
			hex.EncodeToString(token))
		return &t, nil
	}

	return nil, nil
}

// getDetailsTimestampVoteKey returns the key for a auth timestamp in the
// key-value store cache.
func getDetailsTimestampKey(token []byte) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	key := strings.Replace(detailsTimestampKey, "{shorttoken}", t, 1)
	return key, nil
}

// timestampIsFinal returns whether the timestamp is considered to be final and
// will not change in the future. Once the TxID is present then the timestamp
// is considered to be final since it has been included in a DCR transaction.
func timestampIsFinal(t ticketvote.Timestamp) bool {
	return t.TxID != ""
}
