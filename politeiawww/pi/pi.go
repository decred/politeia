// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/pi"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/config"
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

	// Plugin settings
	textFileSizeMax    uint32 // In bytes
	imageFileCountMax  uint32
	imageFileSizeMax   uint32 // In bytes
	nameLengthMin      uint32 // In characters
	nameLengthMax      uint32 // In characters
	nameSupportedChars []string
}

// HandlePolicy is the request handler for the pi v1 Policy route.
func (p *Pi) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	pr, err := p.processPolicy(r.Context())
	if err != nil {
		respondWithError(w, r,
			"HandlePolicy: processPolicy: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pr)
}

// HandleProposals is the request handler for the pi v1 Proposals route.
func (p *Pi) HandleProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleProposals")

	var ps v1.Proposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ps); err != nil {
		respondWithError(w, r, "HandleProposals: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleDetails: GetSessionUser: %v", err)
		return
	}

	psr, err := p.processProposals(r.Context(), ps, u)
	if err != nil {
		respondWithError(w, r,
			"HandleProposals: processProposals: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, psr)
}

// HandleVoteInventory is the request handler for the pi v1 VoteInventory
// route.
func (p *Pi) HandleVoteInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleVoteInventory")

	vir, err := p.processVoteInventory(r.Context())
	if err != nil {
		respondWithError(w, r,
			"HandleVoteInventory: processVoteInventory: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vir)
}

// New returns a new Pi context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, s *sessions.Sessions, plugins []pdv1.Plugin) (*Pi, error) {
	// Parse pi plugin settings
	var (
		textFileSizeMax    uint32
		imageFileCountMax  uint32
		imageFileSizeMax   uint32
		nameLengthMin      uint32
		nameLengthMax      uint32
		nameSupportedChars []string
	)
	for _, v := range plugins {
		if v.ID != pi.PluginID {
			// Not the pi plugin; skip
			continue
		}
		for _, s := range v.Settings {
			switch s.Key {
			case pi.SettingKeyTextFileSizeMax:
				u, err := strconv.ParseUint(s.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				textFileSizeMax = uint32(u)
			case pi.SettingKeyImageFileCountMax:
				u, err := strconv.ParseUint(s.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileCountMax = uint32(u)
			case pi.SettingKeyImageFileSizeMax:
				u, err := strconv.ParseUint(s.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				imageFileSizeMax = uint32(u)
			case pi.SettingKeyProposalNameLengthMin:
				u, err := strconv.ParseUint(s.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMin = uint32(u)
			case pi.SettingKeyProposalNameLengthMax:
				u, err := strconv.ParseUint(s.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				nameLengthMax = uint32(u)
			case pi.SettingKeyProposalNameSupportedChars:
				var sc []string
				err := json.Unmarshal([]byte(s.Value), &sc)
				if err != nil {
					return nil, err
				}
				nameSupportedChars = sc
			default:
				// Skip unknown settings
				log.Warnf("Unknown plugin setting %v; Skipping...", s.Key)
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
	}

	return &Pi{
		cfg:                cfg,
		politeiad:          pdc,
		userdb:             udb,
		sessions:           s,
		textFileSizeMax:    textFileSizeMax,
		imageFileCountMax:  imageFileCountMax,
		imageFileSizeMax:   imageFileSizeMax,
		nameLengthMin:      nameLengthMin,
		nameLengthMax:      nameLengthMax,
		nameSupportedChars: nameSupportedChars,
	}, nil
}
