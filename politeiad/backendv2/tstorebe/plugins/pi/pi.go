// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

var (
	_ plugins.PluginClient = (*piPlugin)(nil)
)

// piPlugin satisfies the plugins PluginClient interface.
type piPlugin struct {
	backend backend.Backend

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string

	// Plugin settings
	textFileCountMax           uint32
	textFileSizeMax            uint32 // In bytes
	imageFileCountMax          uint32
	imageFileSizeMax           uint32 // In bytes
	proposalNameSupportedChars string // JSON encoded []string
	proposalNameLengthMin      uint32 // In characters
	proposalNameLengthMax      uint32 // In characters
	proposalNameRegexp         *regexp.Regexp
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Setup() error {
	log.Tracef("pi Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("pi Cmd: %v %x %v %v", treeID, token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("pi Hook: %v %x %v", plugins.Hooks[h], token, treeID)

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypePluginPre:
		return p.hookPluginPre(treeID, token, payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("pi Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Settings() []backend.PluginSetting {
	log.Tracef("pi Settings")

	return []backend.PluginSetting{
		{
			Key:   pi.SettingKeyTextFileSizeMax,
			Value: strconv.FormatUint(uint64(p.textFileSizeMax), 10),
		},
		{
			Key:   pi.SettingKeyImageFileCountMax,
			Value: strconv.FormatUint(uint64(p.imageFileCountMax), 10),
		},
		{
			Key:   pi.SettingKeyImageFileCountMax,
			Value: strconv.FormatUint(uint64(p.imageFileCountMax), 10),
		},
		{
			Key:   pi.SettingKeyImageFileSizeMax,
			Value: strconv.FormatUint(uint64(p.imageFileSizeMax), 10),
		},
		{
			Key:   pi.SettingKeyProposalNameLengthMin,
			Value: strconv.FormatUint(uint64(p.proposalNameLengthMin), 10),
		},
		{
			Key:   pi.SettingKeyProposalNameLengthMax,
			Value: strconv.FormatUint(uint64(p.proposalNameLengthMax), 10),
		},
		{
			Key:   pi.SettingKeyProposalNameSupportedChars,
			Value: p.proposalNameSupportedChars,
		},
	}
}

// New returns a new piPlugin.
func New(backend backend.Backend, settings []backend.PluginSetting, dataDir string) (*piPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, pi.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup plugin setting default values
	var (
		textFileSizeMax    = pi.SettingTextFileSizeMax
		imageFileCountMax  = pi.SettingImageFileCountMax
		imageFileSizeMax   = pi.SettingImageFileSizeMax
		nameLengthMin      = pi.SettingProposalNameLengthMin
		nameLengthMax      = pi.SettingProposalNameLengthMax
		nameSupportedChars = pi.SettingProposalNameSupportedChars
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case pi.SettingKeyTextFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			textFileSizeMax = uint32(u)
		case pi.SettingKeyImageFileCountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileCountMax = uint32(u)
		case pi.SettingKeyImageFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileSizeMax = uint32(u)
		case pi.SettingKeyProposalNameLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMin = uint32(u)
		case pi.SettingKeyProposalNameLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMax = uint32(u)
		case pi.SettingKeyProposalNameSupportedChars:
			var sc []string
			err := json.Unmarshal([]byte(v.Value), &sc)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameSupportedChars = sc
		default:
			return nil, fmt.Errorf("invalid plugin setting: %v", v.Key)
		}
	}

	// Setup proposal name regex
	rexp, err := util.Regexp(nameSupportedChars, uint64(nameLengthMin),
		uint64(nameLengthMax))
	if err != nil {
		return nil, fmt.Errorf("proposal name regexp: %v", err)
	}

	// Encode the supported chars so that they can be returned as a
	// plugin setting string.
	b, err := json.Marshal(nameSupportedChars)
	if err != nil {
		return nil, err
	}
	nameSupportedCharsString := string(b)

	return &piPlugin{
		dataDir:                    dataDir,
		backend:                    backend,
		textFileSizeMax:            textFileSizeMax,
		imageFileCountMax:          imageFileCountMax,
		imageFileSizeMax:           imageFileSizeMax,
		proposalNameLengthMin:      nameLengthMin,
		proposalNameLengthMax:      nameLengthMax,
		proposalNameSupportedChars: nameSupportedCharsString,
		proposalNameRegexp:         rexp,
	}, nil
}
