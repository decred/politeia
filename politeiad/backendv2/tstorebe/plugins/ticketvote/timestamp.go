// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// timestampKeyVote is the key for a ticket vote timestamp entry in the
	// key-value store cache.
	timestampKeyVote = "timestamp-vote-{shorttoken}-{page}-{index}"

	// timestampKeyAuth is the key for a vote auth timestamp entry in the
	// key-value store cache.
	timestampKeyAuth = "timestamp-auth-{shorttoken}-{index}"

	// timestampKeyDetails is the key for a vote details timestamp entry in the
	// key-value store cache.
	timestampKeyDetails = "timestamp-details-{shorttoken}"
)

// cacheFinalVoteTimestamps accepts a slice of vote timestamps, it collects the
// final timestamps then stores them in the key-value store.
func (p *ticketVotePlugin) cacheFinalVoteTimestamps(token []byte, vts []ticketvote.Timestamp, page uint32) error {
	// Collect final timestamps
	fvts := make([]ticketvote.Timestamp, 0, len(vts))
	for _, ts := range vts {
		if timestampIsFinal(ts) {
			fvts = append(fvts, ts)
		}
	}

	// Store final timestamp
	err := p.saveVoteTimestamps(token, fvts, page)
	if err != nil {
		return err
	}

	log.Debugf("Cached final vote timestamps of %v/%v",
		len(fvts), len(vts))
	return nil
}

// saveTimestamps saves a slice of vote timestamps to the key-value cache.
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
	// Setup the timestamps
	keys := make([]string, 0, pageSize)
	for i := uint32(1); i <= pageSize; i++ {
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
	ts := make([]ticketvote.Timestamp, 0, pageSize)
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

	// XXX add debug statement
	return ts, nil
}

// getVoteTimestampVoteKey returns the key for a vote timestamp in the key-value
// store cache.
func getVoteTimestampKey(token []byte, page, index uint32) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	pageStr := strconv.FormatUint(uint64(page), 10)
	indexStr := strconv.FormatUint(uint64(index), 10)
	key := strings.Replace(timestampKeyVote, "{shorttoken}", t, 1)
	key = strings.Replace(key, "{page}", pageStr, 1)
	key = strings.Replace(key, "{index}", indexStr, 1)
	return key, nil
}

// parseTimestampKeyVote parses the item index from a vote timestamp key.
func parseVoteTimestampKey(key string) (uint32, error) {
	s := strings.Split(key, "-")
	if len(s) != 5 {
		return 0, errors.Errorf("invalid timestamp key")
	}
	index, err := strconv.ParseUint(s[4], 10, 64)
	if err != nil {
		return 0, err
	}
	return uint32(index), nil
}

// timestampIsFinal returns whether the timestamp is considered to be final and
// will not change in the future. Once the TxID is present then the timestamp
// is considered to be final since it has been included in a DCR transaction.
func timestampIsFinal(t ticketvote.Timestamp) bool {
	return t.TxID != ""
}
