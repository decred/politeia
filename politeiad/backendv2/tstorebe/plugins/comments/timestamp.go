// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// timestampKey is the key for a timestamp entry in the key-value store
	// cache.
	timestampKey = "timestamp-{shorttoken}-{commentID}"
)

// saveTimestamps saves a list of timestamps to the key-value cache.
func (p *commentsPlugin) saveTimestamps(token []byte, ts map[uint32]comments.CommentTimestamp) error {
	// Setup the blob entries
	blobs := make(map[string][]byte, len(ts))
	for cid, v := range ts {
		k, err := newTimestampKey(token, cid)
		if err != nil {
			return err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		blobs[k] = b
	}

	// Save the blob entries
	return p.tstore.CachePut(blobs, false)
}

// cachedTimestamps returns cached comment timestamps if they exist. An entry
// will not exist in the returned map if a timestamp was not found in the cache
// for a comment ID.
func (p *commentsPlugin) cachedTimestamps(token []byte, commentIDs []uint32) (map[uint32]*comments.CommentTimestamp, error) {
	// Setup the timestamp keys
	keys := make([]string, 0, len(commentIDs))
	for _, cid := range commentIDs {
		k, err := newTimestampKey(token, cid)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}

	// Get the timestamp blob entries
	blobs, err := p.tstore.CacheGet(keys)
	if err != nil {
		return nil, err
	}

	// Decode the timestamps
	ts := make(map[uint32]*comments.CommentTimestamp, len(blobs))
	for k, v := range blobs {
		var t comments.CommentTimestamp
		err := json.Unmarshal(v, &t)
		if err != nil {
			return nil, err
		}
		cid, err := parseTimestampKey(k)
		if err != nil {
			return nil, err
		}
		ts[cid] = &t
	}

	return ts, nil
}

// newTimestampKey returns the key for a timestamp in the key-value store
// cache.
func newTimestampKey(token []byte, commentID uint32) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	cid := strconv.FormatUint(uint64(commentID), 10)
	key := strings.Replace(timestampKey, "{shorttoken}", t, 1)
	key = strings.Replace(key, "{commentID}", cid, 1)
	return key, nil
}

// parseTimestampKey parses the comment ID from a timestamp key.
func parseTimestampKey(key string) (uint32, error) {
	s := strings.Split(key, "-")
	if len(s) != 3 {
		return 0, errors.Errorf("invalid timestamp key")
	}
	cid, err := strconv.ParseUint(s[2], 10, 64)
	if err != nil {
		return 0, err
	}
	return uint32(cid), nil
}

// timestampIsFinal returns whether the timestamp is considered to be final and
// will not change in the future. Once the TxID is present then the timestamp
// is considered to be final since it has been included in a DCR transaction.
func timestampIsFinal(t comments.Timestamp) bool {
	return t.TxID != ""
}
