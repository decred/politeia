// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
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
	tstore  plugins.TstoreClient

	// statuses holds proposal statuses and various proposal metadata in an
	// in-memory cache to improve the performance of determining the proposal
	// statuses on runtime.
	statuses proposalStatuses

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Plugin settings
	textFileCountMax        uint32
	textFileSizeMax         uint32 // In bytes
	imageFileCountMax       uint32
	imageFileSizeMax        uint32 // In bytes
	titleSupportedChars     string // JSON encoded []string
	titleLengthMin          uint32 // In characters
	titleLengthMax          uint32 // In characters
	titleRegexp             *regexp.Regexp
	proposalAmountMin       uint64 // In cents
	proposalAmountMax       uint64 // In cents
	proposalStartDateMin    int64  // Seconds from current time
	proposalEndDateMax      int64  // Seconds from current time
	proposalDomainsEncoded  string // JSON encoded []string
	proposalDomains         map[string]struct{}
	billingStatusChangesMax uint32
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
func (p *piPlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("pi Cmd: %x %v %v", token, cmd, payload)

	switch cmd {
	case pi.CmdSetBillingStatus:
		return p.cmdSetBillingStatus(token, payload)
	case pi.CmdSummary:
		return p.cmdSummary(token)
	case pi.CmdBillingStatusChanges:
		return p.cmdBillingStatusChanges(token)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("pi Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypePluginPre:
		return p.hookPluginPre(payload)
	}

	return nil
}

// Fsck performs a plugin file system check. The plugin is provided with the
// tokens for all records in the backend.
//
// This function satisfies the plugins PluginClient interface.
func (p *piPlugin) Fsck(tokens [][]byte) error {
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
			Key:   pi.SettingKeyTitleLengthMin,
			Value: strconv.FormatUint(uint64(p.titleLengthMin), 10),
		},
		{
			Key:   pi.SettingKeyTitleLengthMax,
			Value: strconv.FormatUint(uint64(p.titleLengthMax), 10),
		},
		{
			Key:   pi.SettingKeyTitleSupportedChars,
			Value: p.titleSupportedChars,
		},
		{
			Key:   pi.SettingKeyProposalAmountMin,
			Value: strconv.FormatUint(p.proposalAmountMin, 10),
		},
		{
			Key:   pi.SettingKeyProposalAmountMax,
			Value: strconv.FormatUint(p.proposalAmountMax, 10),
		},
		{
			Key:   pi.SettingKeyProposalStartDateMin,
			Value: strconv.FormatInt(p.proposalStartDateMin, 10),
		},
		{
			Key:   pi.SettingKeyProposalEndDateMax,
			Value: strconv.FormatInt(p.proposalEndDateMax, 10),
		},
		{
			Key:   pi.SettingKeyProposalDomains,
			Value: p.proposalDomainsEncoded,
		},
		{
			Key:   pi.SettingKeyBillingStatusChangesMax,
			Value: strconv.FormatUint(uint64(p.billingStatusChangesMax), 10),
		},
	}
}

// New returns a new piPlugin.
func New(backend backend.Backend, tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity) (*piPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, pi.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup plugin setting default values
	var (
		textFileSizeMax         = pi.SettingTextFileSizeMax
		imageFileCountMax       = pi.SettingImageFileCountMax
		imageFileSizeMax        = pi.SettingImageFileSizeMax
		titleLengthMin          = pi.SettingTitleLengthMin
		titleLengthMax          = pi.SettingTitleLengthMax
		titleSupportedChars     = pi.SettingTitleSupportedChars
		amountMin               = pi.SettingProposalAmountMin
		amountMax               = pi.SettingProposalAmountMax
		startDateMin            = pi.SettingProposalStartDateMin
		endDateMax              = pi.SettingProposalEndDateMax
		domains                 = pi.SettingProposalDomains
		billingStatusChangesMax = pi.SettingBillingStatusChangesMax
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case pi.SettingKeyTextFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			textFileSizeMax = uint32(u)
		case pi.SettingKeyImageFileCountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileCountMax = uint32(u)
		case pi.SettingKeyImageFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileSizeMax = uint32(u)
		case pi.SettingKeyTitleLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			titleLengthMin = uint32(u)
		case pi.SettingKeyTitleLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			titleLengthMax = uint32(u)
		case pi.SettingKeyTitleSupportedChars:
			err := json.Unmarshal([]byte(v.Value), &titleSupportedChars)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case pi.SettingKeyProposalAmountMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			amountMin = u
		case pi.SettingKeyProposalAmountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			amountMax = u
		case pi.SettingKeyProposalEndDateMax:
			u, err := strconv.ParseInt(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			// Ensure provided max end date is not in the past
			if u < 0 {
				return nil, errors.Errorf("invalid plugin setting %v '%v': "+
					"must be in the future", v.Key, v.Value)
			}
			endDateMax = u
		case pi.SettingKeyProposalDomains:
			err := json.Unmarshal([]byte(v.Value), &domains)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case pi.SettingKeyBillingStatusChangesMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, errors.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			billingStatusChangesMax = uint32(u)

		default:
			return nil, errors.Errorf("invalid plugin setting: %v", v.Key)
		}
	}

	// Setup title regex
	rexp, err := util.Regexp(titleSupportedChars, uint64(titleLengthMin),
		uint64(titleLengthMax))
	if err != nil {
		return nil, errors.Errorf("proposal name regexp: %v", err)
	}

	// Encode the title supported chars so that they
	// can be returned as a plugin setting string.
	b, err := json.Marshal(titleSupportedChars)
	if err != nil {
		return nil, err
	}
	titleSupportedCharsString := string(b)

	// Encode the proposal domains so that they can be returned as a
	// plugin setting string.
	b, err = json.Marshal(domains)
	if err != nil {
		return nil, err
	}
	domainsString := string(b)

	// Translate domains slice to a Map[string]string.
	domainsMap := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		domainsMap[d] = struct{}{}
	}

	return &piPlugin{
		dataDir:                 dataDir,
		identity:                id,
		backend:                 backend,
		textFileSizeMax:         textFileSizeMax,
		tstore:                  tstore,
		imageFileCountMax:       imageFileCountMax,
		imageFileSizeMax:        imageFileSizeMax,
		titleLengthMin:          titleLengthMin,
		titleLengthMax:          titleLengthMax,
		titleSupportedChars:     titleSupportedCharsString,
		titleRegexp:             rexp,
		proposalAmountMin:       amountMin,
		proposalAmountMax:       amountMax,
		proposalStartDateMin:    startDateMin,
		proposalEndDateMax:      endDateMax,
		proposalDomainsEncoded:  domainsString,
		proposalDomains:         domainsMap,
		billingStatusChangesMax: billingStatusChangesMax,
		statuses: proposalStatuses{
			data:    make(map[string]*statusEntry, statusesCacheLimit),
			entries: list.New(),
		},
	}, nil
}
