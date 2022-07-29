// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// settings contains the plugin settings.
type settings struct {
	Host              *url.URL
	UsernameChars     []string
	UsernameMinLength uint32
	UsernameMaxLength uint32
	PasswordMinLength uint32
	PasswordMaxLength uint32
	ContactTypes      map[string]struct{}

	// usernameRegexp is used to validate usernames.
	usernameRegexp *regexp.Regexp
}

func newSettings(newSettings []app.Setting) (*settings, error) {
	defaultHost, err := url.Parse("https://localhost:3000")
	if err != nil {
		return nil, err
	}

	// Default plugin settings
	s := &settings{
		Host:              defaultHost,
		UsernameChars:     []string{"A-z", "0-9", "_"},
		UsernameMinLength: 3,
		UsernameMaxLength: 15,
		PasswordMinLength: 8,
		PasswordMaxLength: 128,
		ContactTypes: map[string]struct{}{
			contactTypeEmail: {},
		},
		usernameRegexp: nil, // Set below
	}

	// Update the defaults with runtime provided settings
	err = s.update(newSettings)
	if err != nil {
		return nil, err
	}

	// Build the validation regular expressions
	s.usernameRegexp, err = util.Regexp(s.UsernameChars,
		uint64(s.UsernameMinLength), uint64(s.UsernameMaxLength))
	if err != nil {
		return nil, err
	}

	return s, nil
}

// update updates the plugin settings.
func (s *settings) update(newSettings []app.Setting) error {
	for _, v := range newSettings {
		err := s.parseSetting(v)
		if err != nil {
			return errors.Errorf("failed to parse setting %+v: %v", v, err)
		}
		log.Infof("Plugin setting %v updated to %v", v.Name, v.Value)
	}
	return nil
}

// parseSetting parses the plugin setting and updates the settings context.
func (s *settings) parseSetting(v app.Setting) error {
	switch v.Name {
	case v1.SettingsUsernameChars:
		var chars []string
		err := json.Unmarshal([]byte(v.Value), &chars)
		if err != nil {
			return err
		}
		s.UsernameChars = chars

	case v1.SettingUsernameMinLength:
		u, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return err
		}
		s.UsernameMinLength = uint32(u)

	case v1.SettingUsernameMaxLength:
		u, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return err
		}
		s.UsernameMaxLength = uint32(u)

	case v1.SettingPasswordMinLength:
		u, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return err
		}
		s.PasswordMinLength = uint32(u)

	case v1.SettingPasswordMaxLength:
		u, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return err
		}
		s.PasswordMaxLength = uint32(u)

	case v1.SettingContactTypes:
		// TODO

	case v1.SettingHost:
		u, err := url.Parse(v.Value)
		if err != nil {
			return err
		}
		if !u.IsAbs() {
			u.Scheme = "https"
		}
		s.Host = u

	default:
		return errors.Errorf("setting name not recognized")
	}

	return nil
}

// supportedContactTypes contains the contact types that are supported by
// this plugin.
var supportedContactTypes = map[string]struct{}{
	contactTypeEmail: {},
}
