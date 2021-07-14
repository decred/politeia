// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"
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

// piPlugin is the tstore backend implementation of the pi plugin. The pi
// plugin extends a record with functionality specific to the decred proposal
// system.
//
// piPlugin satisfies the plugins PluginClient interface.
type piPlugin struct {
	backend backend.Backend

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

// Write executes a read/write plugin command. All operations are executed
// atomically by tstore when using this method. The plugin does not need to
// worry about concurrency issues.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Write(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("pi Write: %x %v %v", token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Read executes a read-only plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Read(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("pi Read: %x %v %v", token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Hook(tstore plugins.TstoreClient, h plugins.HookT, payload string) error {
	log.Tracef("pi Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookRecordNewPre:
		return p.hookRecordNewPre(payload)
	case plugins.HookRecordEditPre:
		return p.hookRecordEditPre(payload)
	case plugins.HookPluginWritePre:
		return p.hookPluginWritePre(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Fsck() error {
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
func New(backend backend.Backend, settings []backend.PluginSetting) (*piPlugin, error) {
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
