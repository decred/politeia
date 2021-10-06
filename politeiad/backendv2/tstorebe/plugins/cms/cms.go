// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/util"
)

var (
	_ plugins.PluginClient = (*cmsPlugin)(nil)
)

// cmsPlugin is the tstore backend implementation of the cms plugin. The cms
// plugin extends a record with functionality specific to the decred proposal
// system.
//
// cmsPlugin satisfies the plugins PluginClient interface.
type cmsPlugin struct {
	backend         backend.Backend
	tstore          plugins.TstoreClient
	activeNetParams *chaincfg.Params

	// dataDir is the cms plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Plugin settings
	textFileCountMax           uint32
	textFileSizeMax            uint32 // In bytes
	imageFileCountMax          uint32
	imageFileSizeMax           uint32 // In bytes
	mdsCountMax                uint32
	mdsSizeMax                 uint32
	validMimeTypesEncoded      string
	lineItemColLengthMax       uint32
	lineItemColLengthMin       uint32
	nameLengthMax              uint32
	nameLengthMin              uint32
	locationLengthMax          uint32
	locationLengthMin          uint32
	contactLengthMax           uint32
	contactLengthMin           uint32
	statementLengthMax         uint32
	statementLengthMin         uint32
	contractorRateMax          uint32
	contractorRateMin          uint32
	invoiceFieldSupportedChars string
	invoiceFieldRegexp         *regexp.Regexp
	nameLocationSupportedChars string
	nameRegexp                 *regexp.Regexp
	locationRegexp             *regexp.Regexp
	contactSupportedChars      string
	contactRegexp              *regexp.Regexp
	statementSupportedChars    string
	statementRegexp            *regexp.Regexp
	lineItemTypesEncoded       string
	lineItemTypes              map[string]struct{}
	invoiceDomainsEncoded      string
	invoiceDomains             map[string]struct{}
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Setup() error {
	log.Tracef("cms Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Cmd(token []byte, cmd, payload string) (string, error) {
	log.Tracef("cms Cmd: %x %v %v", token, cmd, payload)

	switch cmd {
	case cms.CmdSetInvoiceStatus:
		return c.cmdSetInvoiceStatus(token, payload)
	case cms.CmdSummary:
		return c.cmdSummary(token)
	case cms.CmdInvoiceStatusChanges:
		return c.cmdInvoiceStatusChanges(token)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("cms Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return c.hookNewRecordPre(payload)
	case plugins.HookTypeEditRecordPre:
		return c.hookEditRecordPre(payload)
	case plugins.HookTypePluginPre:
		return c.hookPluginPre(payload)
	}

	return nil
}

// Fsck performs a plugin file system check. The plugin is provided with the
// tokens for all records in the backend.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Fsck(tokens [][]byte) error {
	log.Tracef("cms Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (c *cmsPlugin) Settings() []backend.PluginSetting {
	log.Tracef("cms Settings")

	return []backend.PluginSetting{
		{
			Key:   cms.SettingKeyTextFileSizeMax,
			Value: strconv.FormatUint(uint64(c.textFileSizeMax), 10),
		},
		{
			Key:   cms.SettingKeyImageFileCountMax,
			Value: strconv.FormatUint(uint64(c.imageFileCountMax), 10),
		},
		{
			Key:   cms.SettingKeyImageFileSizeMax,
			Value: strconv.FormatUint(uint64(c.imageFileSizeMax), 10),
		},
		{
			Key:   cms.SettingKeyMDsCountMax,
			Value: strconv.FormatUint(uint64(c.mdsCountMax), 10),
		},
		{
			Key:   cms.SettingKeyMDsSizeMax,
			Value: strconv.FormatUint(uint64(c.mdsSizeMax), 10),
		},
		{
			Key:   cms.SettingKeyValidMIMETypes,
			Value: c.validMimeTypesEncoded,
		},
		{
			Key:   cms.SettingKeyLineItemColLengthMax,
			Value: strconv.FormatUint(uint64(c.lineItemColLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyLineItemColLengthMin,
			Value: strconv.FormatUint(uint64(c.lineItemColLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyNameLengthMax,
			Value: strconv.FormatUint(uint64(c.nameLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyNameLengthMin,
			Value: strconv.FormatUint(uint64(c.nameLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyLocationLengthMax,
			Value: strconv.FormatUint(uint64(c.locationLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyLocationLengthMin,
			Value: strconv.FormatUint(uint64(c.locationLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyContactLengthMax,
			Value: strconv.FormatUint(uint64(c.contactLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyContactLengthMin,
			Value: strconv.FormatUint(uint64(c.contactLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyStatementLengthMax,
			Value: strconv.FormatUint(uint64(c.statementLengthMax), 10),
		},
		{
			Key:   cms.SettingKeyStatementLengthMin,
			Value: strconv.FormatUint(uint64(c.statementLengthMin), 10),
		},
		{
			Key:   cms.SettingKeyStatementSupportedChars,
			Value: c.statementSupportedChars,
		},
		{
			Key:   cms.SettingKeyInvoiceFieldSupportedChars,
			Value: c.invoiceFieldSupportedChars,
		},
		{
			Key:   cms.SettingKeyNameLocationSupportedChars,
			Value: c.nameLocationSupportedChars,
		},
		{
			Key:   cms.SettingKeyContactSupportedChars,
			Value: c.contactSupportedChars,
		},
		{
			Key:   cms.SettingKeyLineItemTypes,
			Value: c.lineItemTypesEncoded,
		},
		{
			Key:   cms.SettingKeyInvoiceDomains,
			Value: c.invoiceDomainsEncoded,
		},
	}
}

// New returns a new cmsPlugin.
func New(backend backend.Backend, tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*cmsPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, cms.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup plugin setting default values
	var (
		textFileSizeMax            = cms.SettingTextFileSizeMax
		imageFileCountMax          = cms.SettingImageFileCountMax
		imageFileSizeMax           = cms.SettingImageFileSizeMax
		nameLengthMax              = cms.SettingNameLengthMax
		nameLengthMin              = cms.SettingNameLengthMin
		mdsCountMax                = cms.SettingMdsCountMax
		mdsSizeMax                 = cms.SettingMDSizeMax
		validMimeTypes             = cms.SettingValidMIMETypes
		lineItemColLengthMax       = cms.SettingLineItemColLengthMax
		lineItemColLengthMin       = cms.SettingLineItemColLengthMin
		locationLengthMax          = cms.SettingLocationLengthMax
		locationLengthMin          = cms.SettingLocationLengthMin
		contactLengthMax           = cms.SettingContactLengthMax
		contactLengthMin           = cms.SettingContactLengthMin
		statementLengthMax         = cms.SettingSponsorStatementLengthMax
		statementLengthMin         = cms.SettingSponsorStatementLengthMin
		invoiceFieldSupportedChars = cms.SettingInvoiceFieldSupportedChars
		nameLocationSupportedChars = cms.SettingNameLocationSupportedChars
		contactSupportedChars      = cms.SettingContactSupportedChars
		statementSupportedChars    = cms.SettingSponsorStatementSupportedChars
		lineItemTypes              = cms.SettingLineItemTypes
		invoiceDomains             = cms.SettingInvoiceDomains
		contractorRateMin          = cms.SettingContractorRateMin
		contractorRateMax          = cms.SettingContractorRateMax
	)

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case cms.SettingKeyTextFileSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			textFileSizeMax = uint32(u)
		case cms.SettingKeyImageFileCountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			imageFileCountMax = uint32(u)
		case cms.SettingKeyMDsCountMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			mdsCountMax = uint32(u)
		case cms.SettingKeyMDsSizeMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			mdsSizeMax = uint32(u)
		case cms.SettingKeyValidMIMETypes:
			err := json.Unmarshal([]byte(v.Value), &validMimeTypes)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyLineItemColLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			lineItemColLengthMax = uint32(u)
		case cms.SettingKeyLineItemColLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			lineItemColLengthMin = uint32(u)
		case cms.SettingKeyNameLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMax = uint32(u)
		case cms.SettingKeyNameLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			nameLengthMin = uint32(u)
		case cms.SettingKeyLocationLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			locationLengthMax = uint32(u)
		case cms.SettingKeyLocationLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			locationLengthMin = uint32(u)
		case cms.SettingKeyContactLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			contactLengthMax = uint32(u)
		case cms.SettingKeyContactLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			contactLengthMin = uint32(u)
		case cms.SettingKeyStatementLengthMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			statementLengthMax = uint32(u)
		case cms.SettingKeyStatementLengthMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			statementLengthMin = uint32(u)
		case cms.SettingKeyContractorRateMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			contractorRateMin = uint32(u)
		case cms.SettingKeyContractorRateMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
			contractorRateMax = uint32(u)
		case cms.SettingKeyInvoiceFieldSupportedChars:
			err := json.Unmarshal([]byte(v.Value), &invoiceFieldSupportedChars)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyNameLocationSupportedChars:
			err := json.Unmarshal([]byte(v.Value), &nameLocationSupportedChars)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyContactSupportedChars:
			err := json.Unmarshal([]byte(v.Value), &contactSupportedChars)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyStatementSupportedChars:
			err := json.Unmarshal([]byte(v.Value), &statementSupportedChars)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyLineItemTypes:
			err := json.Unmarshal([]byte(v.Value), &lineItemTypes)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		case cms.SettingKeyInvoiceDomains:
			err := json.Unmarshal([]byte(v.Value), &invoiceDomains)
			if err != nil {
				return nil, fmt.Errorf("invalid plugin setting %v '%v': %v",
					v.Key, v.Value, err)
			}
		default:
			return nil, fmt.Errorf("invalid plugin setting: %v", v.Key)
		}
	}

	// Encode the valid mime types so they can be returned as a plugin
	// setting string.
	b, err := json.Marshal(validMimeTypes)
	if err != nil {
		return nil, err
	}
	validMimeTypesString := string(b)

	// Setup invoice field regex
	invoiceFieldRegexp, err := util.Regexp(invoiceFieldSupportedChars, uint64(lineItemColLengthMin),
		uint64(lineItemColLengthMax))
	if err != nil {
		return nil, fmt.Errorf("invoice field regexp: %v", err)
	}

	// Encode the invoice field supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(invoiceFieldSupportedChars)
	if err != nil {
		return nil, err
	}
	invoiceFieldSupportedCharsString := string(b)

	// Setup name field regex
	nameRegexp, err := util.Regexp(nameLocationSupportedChars, uint64(nameLengthMin),
		uint64(locationLengthMax))
	if err != nil {
		return nil, fmt.Errorf("name field regexp: %v", err)
	}

	// Setup location field regex
	locationRegexp, err := util.Regexp(nameLocationSupportedChars, uint64(nameLengthMin),
		uint64(locationLengthMax))
	if err != nil {
		return nil, fmt.Errorf("location field regexp: %v", err)
	}

	// Encode the name/location supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(nameLocationSupportedChars)
	if err != nil {
		return nil, err
	}
	nameLocationSupportedCharsString := string(b)

	// Setup contact field regex
	contactRegexp, err := util.Regexp(contactSupportedChars, uint64(contactLengthMin),
		uint64(contactLengthMax))
	if err != nil {
		return nil, fmt.Errorf("contact field regexp: %v", err)
	}

	// Encode the contact supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(contactSupportedChars)
	if err != nil {
		return nil, err
	}
	contactSupportedCharsString := string(b)

	// Setup statement field regex
	statementRegexp, err := util.RegexpNoLength(statementSupportedChars)
	if err != nil {
		return nil, fmt.Errorf("statement field regexp: %v", err)
	}

	// Encode the statement supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(statementSupportedChars)
	if err != nil {
		return nil, err
	}
	statementSupportedCharsString := string(b)

	// Encode the line item types so that they can be returned as a
	// plugin setting string.
	b, err = json.Marshal(lineItemTypes)
	if err != nil {
		return nil, err
	}
	lineItemTypesEncoded := string(b)

	// Translate line item types slice to a Map[string]string.
	lineItemTypesMap := make(map[string]struct{}, len(lineItemTypes))
	for _, d := range lineItemTypes {
		lineItemTypesMap[d] = struct{}{}
	}

	// Encode the invoice domains so that they can be returned as a
	// plugin setting string.
	b, err = json.Marshal(invoiceDomains)
	if err != nil {
		return nil, err
	}
	invoiceDomainsEncoded := string(b)

	// Translate domains slice to a Map[string]string.
	invoiceDomainsMap := make(map[string]struct{}, len(invoiceDomains))
	for _, d := range invoiceDomains {
		invoiceDomainsMap[d] = struct{}{}
	}

	return &cmsPlugin{
		dataDir:                    dataDir,
		identity:                   id,
		backend:                    backend,
		tstore:                     tstore,
		activeNetParams:            activeNetParams,
		textFileSizeMax:            textFileSizeMax,
		imageFileSizeMax:           imageFileSizeMax,
		imageFileCountMax:          imageFileCountMax,
		mdsCountMax:                mdsCountMax,
		mdsSizeMax:                 mdsSizeMax,
		validMimeTypesEncoded:      validMimeTypesString,
		lineItemColLengthMax:       lineItemColLengthMax,
		lineItemColLengthMin:       lineItemColLengthMin,
		nameLengthMax:              nameLengthMax,
		nameLengthMin:              nameLengthMin,
		locationLengthMax:          locationLengthMax,
		locationLengthMin:          locationLengthMin,
		contactLengthMax:           contactLengthMax,
		contactLengthMin:           contactLengthMin,
		statementLengthMax:         statementLengthMax,
		statementLengthMin:         statementLengthMin,
		contractorRateMax:          contractorRateMax,
		contractorRateMin:          contractorRateMin,
		invoiceFieldSupportedChars: invoiceFieldSupportedCharsString,
		invoiceFieldRegexp:         invoiceFieldRegexp,
		nameLocationSupportedChars: nameLocationSupportedCharsString,
		locationRegexp:             locationRegexp,
		nameRegexp:                 nameRegexp,
		contactSupportedChars:      contactSupportedCharsString,
		contactRegexp:              contactRegexp,
		statementSupportedChars:    statementSupportedCharsString,
		statementRegexp:            statementRegexp,
		lineItemTypesEncoded:       lineItemTypesEncoded,
		lineItemTypes:              lineItemTypesMap,
		invoiceDomainsEncoded:      invoiceDomainsEncoded,
		invoiceDomains:             invoiceDomainsMap,
	}, nil
}
