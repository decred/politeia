// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
)

const (
	AppID = "proposals"
)

func NewApp(settings map[string][]plugin.Setting) (plugin.App, error) {
	return nil, nil
}
