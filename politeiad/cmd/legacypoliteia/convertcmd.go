// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
)

const (
	defaultLegacyDir = "./legacy-politeia-data"
)

func execConvertCmd(args []string) error {
	return nil
}

// decodeVersion returns the version field from the provided JSON payload. This
// function should only be used when the payload contains a single struct with
// a "version" field.
func decodeVersion(payload []byte) (uint, error) {
	data := make(map[string]interface{}, 32)
	err := json.Unmarshal(payload, &data)
	if err != nil {
		return 0, err
	}
	version := uint(data["version"].(float64))
	if version == 0 {
		return 0, fmt.Errorf("version not found")
	}
	return version, nil
}
