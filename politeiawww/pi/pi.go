// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/pi"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// Pi is the context for the pi API.
type Pi struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  *sessions.Sessions
	events    *events.Manager
	mail      *mail.Client
	policy    *v1.PolicyReply
}

// HandlePolicy is the request handler for the pi v1 Policy route.
func (p *Pi) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, p.policy)
}

// New returns a new Pi context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, s *sessions.Sessions, e *events.Manager, m *mail.Client, plugins []pdv2.Plugin) (*Pi, error) {
	// Parse plugin settings
	var (
		textFileSizeMax    uint32
		imageFileCountMax  uint32
		imageFileSizeMax   uint32
		nameLengthMin      uint32
		nameLengthMax      uint32
		nameSupportedChars []string
		amountMin          uint32
		amountMax          uint32
		endDateMax         uint64
		domains            []string
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
			case pi.SettingKeyProposalNameLengthMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMin = uint32(u)
			case pi.SettingKeyProposalNameLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMax = uint32(u)
			case pi.SettingKeyProposalNameSupportedChars:
				var sc []string
				err := json.Unmarshal([]byte(v.Value), &sc)
				if err != nil {
					return nil, err
				}
				nameSupportedChars = sc
			case pi.SettingKeyProposalAmountMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				amountMin = uint32(u)
			case pi.SettingKeyProposalAmountMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				amountMax = uint32(u)
			case pi.SettingKeyProposalEndDateMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				endDateMax = u
			case pi.SettingKeyProposalDomains:
				var ds []string
				err := json.Unmarshal([]byte(v.Value), &ds)
				if err != nil {
					return nil, err
				}
				domains = ds
			default:
				// Skip unknown settings
				log.Warnf("Unknown plugin setting %v; Skipping...", v.Key)
			}
		}
	}

	// Verify all plugin settings have been provided
	switch {
	case textFileSizeMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyTextFileSizeMax)
	case imageFileCountMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyImageFileCountMax)
	case imageFileSizeMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyImageFileSizeMax)
	case nameLengthMin == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalNameLengthMin)
	case nameLengthMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalNameLengthMax)
	case len(nameSupportedChars) == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalNameSupportedChars)
	case amountMin == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalAmountMin)
	case amountMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalAmountMax)
	case endDateMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalEndDateMax)
	case len(domains) == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			pi.SettingKeyProposalDomains)
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
			TextFileSizeMax:    textFileSizeMax,
			ImageFileCountMax:  imageFileCountMax,
			ImageFileSizeMax:   imageFileSizeMax,
			NameLengthMin:      nameLengthMin,
			NameLengthMax:      nameLengthMax,
			NameSupportedChars: nameSupportedChars,
			AmountMin:          amountMin,
			AmountMax:          amountMax,
			EndDateMax:         endDateMax,
			Domains:            domains,
		},
	}

	// Setup event listeners
	p.setupEventListeners()

	return &p, nil
}
