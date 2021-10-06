// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/util"
)

// newTestCmsPlugin returns a cmsPlugin that has been setup for testing.
func newTestCmsPlugin(t *testing.T) (*cmsPlugin, func()) {
	// Create plugin data directory
	dataDir, err := ioutil.TempDir("", cms.PluginID)
	if err != nil {
		t.Fatal(err)
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

	// Encode the valid mime types so they can be returned as a plugin
	// setting string.
	b, err := json.Marshal(validMimeTypes)
	if err != nil {
		t.Fatal(err)
	}
	validMimeTypesString := string(b)

	// Setup invoice field regex
	invoiceFieldRegexp, err := util.Regexp(invoiceFieldSupportedChars, uint64(lineItemColLengthMin),
		uint64(lineItemColLengthMax))
	if err != nil {
		t.Fatal(fmt.Errorf("invoice field regexp: %v", err))
	}

	// Encode the invoice field supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(invoiceFieldSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	invoiceFieldSupportedCharsString := string(b)

	// Setup name field regex
	nameRegexp, err := util.Regexp(nameLocationSupportedChars, uint64(nameLengthMin),
		uint64(nameLengthMax))
	if err != nil {
		t.Fatal(fmt.Errorf("name field regexp: %v", err))
	}

	// Setup location field regex
	locationRegexp, err := util.Regexp(nameLocationSupportedChars, uint64(nameLengthMin),
		uint64(locationLengthMax))
	if err != nil {
		t.Fatal(fmt.Errorf("location field regexp: %v", err))
	}

	// Encode the name/location supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(nameLocationSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	nameLocationSupportedCharsString := string(b)

	// Setup contact field regex
	contactRegexp, err := util.Regexp(contactSupportedChars, uint64(contactLengthMin),
		uint64(contactLengthMax))
	if err != nil {
		t.Fatal(fmt.Errorf("contact field regexp: %v", err))
	}

	// Encode the contact supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(contactSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	contactSupportedCharsString := string(b)

	// Setup statement field regex
	statementRegexp, err := util.RegexpNoLength(statementSupportedChars)
	if err != nil {
		t.Fatal(fmt.Errorf("statement field regexp: %v", err))
	}

	// Encode the statement supported chars so that they
	// can be returned as a plugin setting string.
	b, err = json.Marshal(statementSupportedChars)
	if err != nil {
		t.Fatal(err)
	}
	statementSupportedCharsString := string(b)

	// Encode the line item types so that they can be returned as a
	// plugin setting string.
	b, err = json.Marshal(lineItemTypes)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	invoiceDomainsEncoded := string(b)

	// Translate domains slice to a Map[string]string.
	invoiceDomainsMap := make(map[string]struct{}, len(invoiceDomains))
	for _, d := range invoiceDomains {
		invoiceDomainsMap[d] = struct{}{}
	}

	// Setup plugin context
	c := cmsPlugin{
		dataDir:                    dataDir,
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
		activeNetParams:            chaincfg.TestNet3Params(),
	}

	return &c, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}
