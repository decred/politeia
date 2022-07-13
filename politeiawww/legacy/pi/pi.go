// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/pi"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy/events"
	"github.com/decred/politeia/politeiawww/legacy/mail"
	"github.com/decred/politeia/politeiawww/legacy/sessions"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// Pi is the context for the pi API.
type Pi struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	mail      mail.Mailer
	sessions  *sessions.Sessions
	events    *events.Manager
	policy    *v1.PolicyReply
}

// HandlePolicy is the request handler for the pi v1 Policy route.
func (p *Pi) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, p.policy)
}

// HandleSetBillingStatus is the request handler for the pi v1 BillingStatus
// route.
func (p *Pi) HandleSetBillingStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSetBillingStatus")

	var sbs v1.SetBillingStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sbs); err != nil {
		respondWithError(w, r, "HandleSetBillingStatus: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleSetBillingStatus: GetSessionUser: %v", err)
		return
	}

	bsr, err := p.processSetBillingStatus(r.Context(), sbs, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleSetBillingStatus: processSetBillingStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)
}

// HandleBillingStatusChanges is the request handler for the pi v1
// BillingStatusChanges route.
func (p *Pi) HandleBillingStatusChanges(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleBillingStatusChanges")

	var bscs v1.BillingStatusChanges
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bscs); err != nil {
		respondWithError(w, r, "HandleBillingStatusChanges: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	bsr, err := p.processBillingStatusChanges(r.Context(), bscs)
	if err != nil {
		respondWithError(w, r,
			"HandleBillingStatusChanges: processBillingStatusChanges: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)

}

// HandleSummaries is the request handler for the pi v1 Summaries route.
func (p *Pi) HandleSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSummaries")

	var s v1.Summaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		respondWithError(w, r, "HandleSummaries: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	bsr, err := p.processSummaries(r.Context(), s)
	if err != nil {
		respondWithError(w, r,
			"HandleSummaries: processSummaries: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, bsr)
}

// New returns a new Pi context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, m mail.Mailer, s *sessions.Sessions, e *events.Manager, plugins []pdv2.Plugin) (*Pi, error) {
	// Parse plugin settings
	var (
		textFileSizeMax              uint32
		imageFileCountMax            uint32
		imageFileSizeMax             uint32
		titleLengthMin               uint32
		titleLengthMax               uint32
		titleSupportedChars          []string
		amountMin                    uint64
		amountMax                    uint64
		startDateMin                 int64
		endDateMax                   int64
		domains                      []string
		billingStatusChangesMax      uint32
		summariesPageSize            uint32
		billingStatusChangesPageSize uint32
	)
	for _, p := range plugins {
		if p.ID != pi.PluginID {
			// Not the pi plugin; skip
			continue
		}
		for _, v := range p.Settings {
			switch v.Key {
			case pi.SettingKeyTextFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				textFileSizeMax = uint32(u)

			case pi.SettingKeyImageFileCountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileCountMax = uint32(u)

			case pi.SettingKeyImageFileSizeMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileSizeMax = uint32(u)

			case pi.SettingKeyTitleLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				titleLengthMin = uint32(u)

			case pi.SettingKeyTitleLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				titleLengthMax = uint32(u)

			case pi.SettingKeyTitleSupportedChars:
				err := json.Unmarshal([]byte(v.Value), &titleSupportedChars)
				if err != nil {
					return nil, err
				}

			case pi.SettingKeyProposalAmountMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				amountMin = u

			case pi.SettingKeyProposalAmountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				amountMax = u

			case pi.SettingKeyProposalStartDateMin:
				u, err := strconv.ParseInt(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				startDateMin = u

			case pi.SettingKeyProposalEndDateMax:
				u, err := strconv.ParseInt(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				endDateMax = u

			case pi.SettingKeyProposalDomains:
				err := json.Unmarshal([]byte(v.Value), &domains)
				if err != nil {
					return nil, err
				}
				// Ensure no empty strings.
				for _, d := range domains {
					if d == "" {
						return nil, errors.Errorf("proposal domain can not be an empty " +
							"string")
					}
				}

			case pi.SettingKeyBillingStatusChangesMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				billingStatusChangesMax = uint32(u)

			case pi.SettingKeySummariesPageSize:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				summariesPageSize = uint32(u)

			case pi.SettingKeyBillingStatusChangesPageSize:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				billingStatusChangesPageSize = uint32(u)

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
			pi.SettingKeyTextFileSizeMax)
	case imageFileCountMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyImageFileCountMax)
	case imageFileSizeMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyImageFileSizeMax)
	case titleLengthMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyTitleLengthMin)
	case titleLengthMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyTitleLengthMax)
	case len(titleSupportedChars) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyTitleSupportedChars)
	case amountMin == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalAmountMin)
	case amountMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalAmountMax)
	case endDateMax == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalEndDateMax)
	case len(domains) == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalDomains)
	case summariesPageSize == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeySummariesPageSize)
	case billingStatusChangesPageSize == 0:
		return nil, errors.Errorf("plugin setting not found: %v",
			pi.SettingKeyBillingStatusChangesPageSize)
	}

	// Setup pi context
	p := Pi{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
		events:    e,
		mail:      m,
		policy: &v1.PolicyReply{
			TextFileSizeMax:              textFileSizeMax,
			ImageFileCountMax:            imageFileCountMax,
			ImageFileSizeMax:             imageFileSizeMax,
			NameLengthMin:                titleLengthMin,
			NameLengthMax:                titleLengthMax,
			NameSupportedChars:           titleSupportedChars,
			AmountMin:                    amountMin,
			AmountMax:                    amountMax,
			StartDateMin:                 startDateMin,
			EndDateMax:                   endDateMax,
			Domains:                      domains,
			SummariesPageSize:            summariesPageSize,
			BillingStatusChangesPageSize: billingStatusChangesPageSize,
			BillingStatusChangesMax:      billingStatusChangesMax,
		},
	}

	// Setup event listeners
	p.setupEventListeners()

	return &p, nil
}
