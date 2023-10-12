// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package server

import (
	"net"

	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	defaultCSRFMaxAge       uint32 = 60 * 60 * 24    // 1 day in seconds
	defaultSessionMaxAge    uint32 = 60 * 60 * 24    // 1 day in seconds
	defaultReadTimeout      uint32 = 5               // In seconds
	defaultWriteTimeout     uint32 = 60              // In seconds
	defaultReqBodySizeLimit int64  = 3 * 1024 * 1024 // 3 MiB
	defaultPluginBatchLimit uint32 = 20
	defaultListen                  = "4443"
)

type Config struct {
	BuildVersion     string
	HTTPSCert        string // File path
	HTTPSKey         string // File path
	CSRFKey          string // File path
	CSRFMaxAge       uint32
	SessionKey       string // File path
	SessionMaxAge    uint32
	ReadTimeout      uint32
	WriteTimeout     uint32
	ReqBodySizeLimit int64
	PluginBatchLimit uint32
	Listen           string
}

func verifyConfig(cfg *Config) error {
	switch {
	case cfg.HTTPSCert == "":
		return errors.Errorf("https cert setting is missing")
	case cfg.HTTPSKey == "":
		return errors.Errorf("https key setting is missing")
	case cfg.CSRFKey == "":
		return errors.Errorf("csrf key setting is missing")
	case cfg.SessionKey == "":
		return errors.Errorf("session key setting is missing")
	}
	cfg.HTTPSCert = util.CleanAndExpandPath(cfg.HTTPSCert)
	cfg.HTTPSKey = util.CleanAndExpandPath(cfg.HTTPSKey)
	cfg.CSRFKey = util.CleanAndExpandPath(cfg.CSRFKey)
	cfg.SessionKey = util.CleanAndExpandPath(cfg.SessionKey)

	// Set defaults
	if cfg.CSRFMaxAge == 0 {
		cfg.CSRFMaxAge = defaultCSRFMaxAge
	}
	if cfg.SessionMaxAge == 0 {
		cfg.SessionMaxAge = defaultSessionMaxAge
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	if cfg.ReqBodySizeLimit == 0 {
		cfg.ReqBodySizeLimit = defaultReqBodySizeLimit
	}
	if cfg.PluginBatchLimit == 0 {
		cfg.PluginBatchLimit = defaultPluginBatchLimit
	}
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}

	cfg.Listen = net.JoinHostPort("", cfg.Listen)

	return nil
}
