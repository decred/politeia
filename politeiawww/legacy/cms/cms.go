// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/json"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/cms"
	v2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/legacy/sessions"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// Cms is the context for the cms API.
type Cms struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	mail      mail.Mailer
	sessions  *sessions.Sessions
	events    *events.Manager
	policy    *v2.PolicyReply
}

// HandlePolicy is the request handler for the cms v2 Policy route.
func (c *Cms) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, c.policy)
}

// HandleSetInvoiceStatus is the request handler for the cms v2 SetInvoiceStatus
// route.
func (c *Cms) HandleSetInvoiceStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSetInvoiceStatus")

	var sbs v2.SetInvoiceStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sbs); err != nil {
		respondWithError(w, r, "HandleSetInvoiceStatus: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleSetInvoiceStatus: GetSessionUser: %v", err)
		return
	}

	bsr, err := c.processSetInvoiceStatus(r.Context(), sbs, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleSetInvoiceStatus: processSetInvoiceStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)
}

// HandleSummaries is the request handler for the cms v2 Summaries route.
func (c *Cms) HandleSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSummaries")

	var s v2.Summaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		respondWithError(w, r, "HandleSummaries: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeInputInvalid,
			})
		return
	}

	bsr, err := c.processSummaries(r.Context(), s)
	if err != nil {
		respondWithError(w, r,
			"HandleSummaries: processSummaries: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)
}

// HandleInvoiceStatusChanges is the request handler for the cms v2
// InvoiceStatusChanges route.
func (c *Cms) HandleInvoiceStatusChanges(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleInvoiceStatusChanges")

	var bscs v2.InvoiceStatusChanges
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bscs); err != nil {
		respondWithError(w, r, "HandleInvoiceStatusChanges: unmarshal",
			v2.UserErrorReply{
				ErrorCode: v2.ErrorCodeInputInvalid,
			})
		return
	}

	bsr, err := c.processInvoiceStatusChanges(r.Context(), bscs)
	if err != nil {
		respondWithError(w, r,
			"HandleInvoiceStatusChanges: processInvoiceStatusChanges: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)

}

// New returns a new Cms context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, m mail.Mailer, s *sessions.Sessions, e *events.Manager, plugins []pdv2.Plugin) (*Cms, error) {
	// Parse plugin settings
	var (
		textFileSizeMax            uint32
		imageFileCountMax          uint32
		imageFileSizeMax           uint32
		mdsCountMax                uint32
		mdsSizeMax                 uint32
		validMimeTypes             []string
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
		invoiceFieldSupportedChars []string
		usernameSupportChars       []string
		nameLocationSupportedChars []string
		contactSupportedChars      []string
		statementSupportedChars    []string
		lineItemTypes              []string
		invoiceDomains             []string
	)
	for _, p := range plugins {
		if p.ID != cms.PluginID {
			// Not the cms plugin; skip
			continue
		}
		for _, v := range p.Settings {
			switch v.Key {
			case cms.SettingKeyTextFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				textFileSizeMax = uint32(u)
			case cms.SettingKeyImageFileCountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileCountMax = uint32(u)
			case cms.SettingKeyImageFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileSizeMax = uint32(u)
			case cms.SettingKeyMDsCountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				mdsCountMax = uint32(u)
			case cms.SettingKeyMDsSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				mdsSizeMax = uint32(u)
			case cms.SettingKeyValidMIMETypes:
				err := json.Unmarshal([]byte(v.Value), &validMimeTypes)
				if err != nil {
					return nil, err
				}
			case cms.SettingKeyLineItemColLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				lineItemColLengthMin = uint32(u)
			case cms.SettingKeyLineItemColLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				lineItemColLengthMax = uint32(u)
			case cms.SettingKeyNameLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMax = uint32(u)
			case cms.SettingKeyNameLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMin = uint32(u)
			case cms.SettingKeyLocationLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				locationLengthMax = uint32(u)
			case cms.SettingKeyLocationLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				locationLengthMin = uint32(u)
			case cms.SettingKeyContactLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				contactLengthMax = uint32(u)
			case cms.SettingKeyContactLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				contactLengthMin = uint32(u)
			case cms.SettingKeyStatementLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				statementLengthMin = uint32(u)
			case cms.SettingKeyStatementLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				statementLengthMax = uint32(u)
			case cms.SettingKeyInvoiceFieldSupportedChars:
				err := json.Unmarshal([]byte(v.Value), &invoiceFieldSupportedChars)
				if err != nil {
					return nil, err
				}
			case cms.SettingKeyNameLocationSupportedChars:
				err := json.Unmarshal([]byte(v.Value), &nameLocationSupportedChars)
				if err != nil {
					return nil, err
				}
			case cms.SettingKeyContactSupportedChars:
				err := json.Unmarshal([]byte(v.Value), &contactSupportedChars)
				if err != nil {
					return nil, err
				}
			case cms.SettingKeyStatementSupportedChars:
				err := json.Unmarshal([]byte(v.Value), &statementSupportedChars)
				if err != nil {
					return nil, err
				}
			case cms.SettingKeyLineItemTypes:
				err := json.Unmarshal([]byte(v.Value), &lineItemTypes)
				if err != nil {
					return nil, err
				}
				// Ensure no empty strings.
				for _, d := range lineItemTypes {
					if d == "" {
						return nil, errors.Errorf("line item types can not be an empty " +
							"string")
					}
				}
			case cms.SettingKeyInvoiceDomains:
				err := json.Unmarshal([]byte(v.Value), &invoiceDomains)
				if err != nil {
					return nil, err
				}
				// Ensure no empty strings.
				for _, d := range invoiceDomains {
					if d == "" {
						return nil, errors.Errorf("invoice domain can not be an empty " +
							"string")
					}
				}
			default:
				// Skip unknown settings
				log.Warnf("Unknown plugin setting %v; Skipping...", v.Key)
			}
		}
	}

	// Verify all plugin settings have been provided
	switch {
	case textFileSizeMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyTextFileSizeMax)
	case imageFileCountMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyImageFileCountMax)
	case imageFileSizeMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyImageFileSizeMax)
	case mdsCountMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyMDsCountMax)
	case mdsSizeMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyMDsSizeMax)
	case len(validMimeTypes) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyValidMIMETypes)
	case lineItemColLengthMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyLineItemColLengthMax)
	case lineItemColLengthMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyLineItemColLengthMin)
	case locationLengthMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingNameLengthMax)
	case locationLengthMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyLocationLengthMin)
	case contactLengthMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyContactLengthMax)
	case contactLengthMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyContactLengthMin)
	case nameLengthMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyNameLengthMax)
	case nameLengthMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyNameLengthMin)
	case len(invoiceFieldSupportedChars) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyInvoiceFieldSupportedChars)
	case len(nameLocationSupportedChars) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyNameLocationSupportedChars)
	case len(contactSupportedChars) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyContactSupportedChars)
	case len(statementSupportedChars) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyStatementSupportedChars)
	case len(lineItemTypes) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyLineItemTypes)
	case len(invoiceDomains) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			cms.SettingKeyInvoiceDomains)
	}

	// Setup cms context
	c := Cms{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
		events:    e,
		mail:      m,
		policy: &v2.PolicyReply{
			TextFileSizeMax:            textFileSizeMax,
			ImageFileCountMax:          imageFileCountMax,
			ImageFileSizeMax:           imageFileSizeMax,
			NameLengthMin:              nameLengthMin,
			NameLengthMax:              nameLengthMax,
			MDsCountMax:                mdsCountMax,
			MDSizeMax:                  mdsSizeMax,
			ValidMIMETypes:             validMimeTypes,
			LineItemColLengthMin:       lineItemColLengthMin,
			LineItemColLengthMax:       lineItemColLengthMax,
			LocationLengthMax:          locationLengthMax,
			LocationLengthMin:          locationLengthMin,
			ContactLengthMax:           contactLengthMax,
			ContactLengthMin:           contactLengthMin,
			StatementLengthMax:         statementLengthMax,
			StatementLengthMin:         statementLengthMin,
			InvoiceFieldSupportedChars: invoiceFieldSupportedChars,
			UsernameSupportedChars:     usernameSupportChars,
			NameLocationSupportedChars: nameLocationSupportedChars,
			ContactSupportedChars:      contactSupportedChars,
			StatementSupportedChars:    statementSupportedChars,
			Domains:                    invoiceDomains,
			LineItemTypes:              lineItemTypes,
		},
	}

	// Setup event listeners
	c.setupEventListeners()

	return &c, nil
}
