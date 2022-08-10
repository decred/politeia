// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// cmds.go contains the execution logic for the auth plugin commands.

func (p *authp) cmdNewUser(tx *sql.Tx, c app.Cmd) (*app.CmdReply, error) {
	var nu v1.NewUser
	err := json.Unmarshal([]byte(c.Payload), &nu)
	if err != nil {
		return nil, userErr{
			Code: v1.ErrCodeInvalidPayload,
		}
	}

	// Verify the user credentials
	var (
		username = formatUsername(nu.Username)
		password = nu.Password
	)
	err = validateUsername(p.settings, username)
	if err != nil {
		return nil, err
	}
	err = validatePassword(p.settings, password)
	if err != nil {
		return nil, err
	}

	// Verify that the username is unique
	_, err = p.getUserByUsername(tx, username)
	switch {
	case err == nil:
		return nil, userErr{
			Code:    v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("%v is already taken", username),
		}
	case errors.Is(err, errNotFound):
		// The username is unique; continue
	default:
		// All other errors
		return nil, err
	}

	// Verify the contact info and send any external
	// communications, such as an email, that's needed
	// to verify ownership. Contact info is optional.
	contacts := make([]contactInfo, 0)
	if nu.ContactInfo != nil {
		var (
			nc      = nu.ContactInfo
			contact = newContactInfo(string(nc.Type), nc.Contact)
		)
		err = validateContactInfo(p.settings, *contact)
		if err != nil {
			return nil, err
		}
		err = p.sendContactVerification(username, contact)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, *contact)
	}

	// Insert the user into the database
	hashedPass, err := bcryptHash(password)
	if err != nil {
		return nil, err
	}
	var (
		groups = []string{v1.StandardUser}
		u      = newUser(username, hashedPass, groups, contacts)
	)
	err = p.insertUser(tx, *u)
	if err != nil {
		return nil, err
	}

	log.Infof("New user created %v", u)

	// Send the reply
	var nur v1.NewUserReply
	payload, err := json.Marshal(nur)
	if err != nil {
		return nil, err
	}

	return &app.CmdReply{
		Payload: string(payload),
	}, nil
}

func (p *authp) cmdLogin(tx *sql.Tx, c app.Cmd, s *app.Session) (*app.CmdReply, error) {
	var l v1.Login
	err := json.Unmarshal([]byte(c.Payload), &l)
	if err != nil {
		return nil, userErr{
			Code: v1.ErrCodeInvalidPayload,
		}
	}
	var (
		username = l.Username
		password = l.Password
	)
	u, err := p.getUserByUsername(tx, username)
	if err != nil {
		if err == errNotFound {
			return nil, userErr{
				Code: v1.ErrCodeInvalidLogin,
			}
		}
		return nil, err
	}
	if u.Deactivated {
		return nil, userErr{
			Code: v1.ErrCodeAccountDeactivated,
		}
	}
	if u.IsLocked(p.settings.MaxFailedLogins) {
		return nil, userErr{
			Code: v1.ErrCodeAccountLocked,
		}
	}

	// Verify the password
	err = bcrypt.CompareHashAndPassword(u.Password, []byte(password))
	if err != nil {
		// Wrong password. Update the user record with
		// the failed attempt before returning.
		err = p.handleFailedLogin(u.ID)
		if err != nil {
			return nil, err
		}
		return nil, userErr{
			Code: v1.ErrCodeInvalidLogin,
		}
	}

	// Update the session. These changes will be persisted by
	// the server. The plugin doesn't need to save anything.
	sn := newSession(s)
	sn.SetUserID(u.ID)

	// Update and save the user
	u.AddLogin()
	err = p.updateUser(tx, *u)
	if err != nil {
		return nil, err
	}

	// Send the reply
	lr := v1.LoginReply{
		User: convertUser(*u),
	}
	payload, err := json.Marshal(lr)
	if err != nil {
		return nil, err
	}

	return &app.CmdReply{
		Payload: string(payload),
	}, nil
}

func (p *authp) cmdLogout(tx *sql.Tx, c app.Cmd, s *app.Session) (*app.CmdReply, error) {
	// Update the session. These changes will be persisted by
	// the server. The plugin doesn't need to save anything.
	sn := newSession(s)
	sn.SetDel()

	// Send the reply
	payload, err := json.Marshal(v1.LogoutReply{})
	if err != nil {
		return nil, err
	}

	return &app.CmdReply{
		Payload: string(payload),
	}, nil
}

func (p *authp) cmdMe(q querier, c app.Cmd, userID string) (*app.CmdReply, error) {
	// Get the logged in user from the database
	var u *v1.User
	if userID != "" {
		usr, err := p.getUser(q, userID)
		if err != nil {
			// It should not be possible for an invalid
			// user ID to be part of a session, so we
			// don't need to handle not found errors.
			return nil, err
		}
		cu := convertUser(*usr)
		u = &cu
	}

	// Send the reply
	mr := v1.MeReply{
		User: u,
	}
	payload, err := json.Marshal(mr)
	if err != nil {
		return nil, err
	}

	return &app.CmdReply{
		Payload: string(payload),
	}, nil
}

func (p *authp) cmdUpdateGroup(tx *sql.Tx, c app.Cmd, userID string) (*app.CmdReply, error) {
	var g v1.UpdateGroup
	err := json.Unmarshal([]byte(c.Payload), &g)
	if err != nil {
		return nil, userErr{
			Code: v1.ErrCodeInvalidPayload,
		}
	}
	var (
		sessionUserID = userID
		updateUserID  = g.UserID
		group         = g.Group
		action        = g.Action
	)

	// Verify the request
	switch {
	case !validUserID(updateUserID):
		return nil, userErr{
			Code: v1.ErrCodeInvalidUserID,
		}

	case action != v1.ActionAdd && action != v1.ActionDel:
		return nil, userErr{
			Code:    v1.ErrCodeInvalidUserID,
			Context: "action must be either add or del",
		}

	case !p.validGroup(group):
		return nil, userErr{
			Code: v1.ErrCodeInvalidGroup,
		}
	}

	// Verify that the session user is allowed
	// to update the requested user group.
	u, err := p.getUser(tx, sessionUserID)
	if err != nil {
		return nil, err
	}
	if !p.userCanAssignGroup(*u, group) {
		return nil, userErr{
			Code:    v1.ErrCodeNotAuthorized,
			Context: fmt.Sprintf("user is not allowed to update %v group", group),
		}
	}

	// Execute the update
	u, err = p.getUser(tx, updateUserID)
	if err != nil {
		return nil, err
	}
	switch action {
	case v1.ActionAdd:
		// u.AddGroup(group)
	case v1.ActionDel:
		// u.DelGroup(group)
	}
	err = p.updateUser(tx, *u)
	if err != nil {
		return nil, err
	}

	log.Infof("User %v %v group %v", u.Username, action, group)

	// Send the reply
	payload, err := json.Marshal(v1.UpdateGroupReply{})
	if err != nil {
		return nil, err
	}

	return &app.CmdReply{
		Payload: string(payload),
	}, nil
}

// This function updates the contactInfo. The caller must save the changes to
// the database.
func (p *authp) sendContactVerification(username string, c *contactInfo) error {
	// Send the verification communication
	switch c.Type {
	case contactTypeEmail:
		err := p.sendEmailVerification(username, c.Contact, c.Token)
		if err != nil {
			return err
		}
	default:
		return errors.Errorf("invalid contact type %v", c.Type)
	}

	// Record the sent timestamp
	c.TokenSent = append(c.TokenSent, time.Now().Unix())

	log.Debugf("Contact info verification (%v) sent for %v", c.Type, username)

	return nil
}

// handleFailedLogin updates the user's account with a failed login attempt
// and sends a notification to the user if they've reached the max allowed
// number of failed attempts and their account is now locked.
//
// This database update occurs in an error path, which means the database
// transaction provided to the plugin will no be committed. For this reason,
// we must perform the update using a new transaction.
func (p *authp) handleFailedLogin(userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	u, err := p.getUser(tx, userID)
	if err != nil {
		return err
	}
	err = u.AddFailedLogin(p.settings.MaxFailedLogins)
	if err != nil {
		return err
	}
	err = p.updateUser(tx, *u)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			return errors.Errorf("commit err: %v, rollback err: %v", err, err2)
		}
		return errors.WithStack(err)
	}

	if !u.IsLocked(p.settings.MaxFailedLogins) {
		// User has not reached the max allowed
		// failed logins. Nothing else to do.
		return nil
	}

	// The user has reached the max allowed failed
	// logins. Send them a notification letting them
	// know that their account is locked.
	// TODO

	return nil
}

// bcryptHash returns a bycrt hash of the provided string.
func bcryptHash(s string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
}

// formatUsername formats a username to lowercase without any leading or
// trailing spaces.
func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername validates that a username meets the username requirements.
func validateUsername(s settings, username string) error {
	switch {
	case formatUsername(username) != username:
		// Sanity check. The caller should have already done this.
		return errors.Errorf("the username has not been formatted")

	case len(username) < int(s.UsernameMinLength):
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username must be at least %v characters long",
				s.UsernameMinLength),
		}

	case len(username) > int(s.UsernameMaxLength):
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username exceedes the max length of %v characters",
				s.UsernameMaxLength),
		}

	case !s.usernameRegexp.MatchString(username):
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username contains invalid characters; "+
				"valid characters are %v", s.UsernameChars),
		}
	}
	return nil
}

// validatePassword validates that a password meets all password requirements.
func validatePassword(s settings, password string) error {
	switch {
	case len(password) < int(s.PasswordMinLength):
		return userErr{
			Code: v1.ErrCodeInvalidPassword,
			Context: fmt.Sprintf("password must be at least %v characters",
				s.PasswordMinLength),
		}

	case len(password) > int(s.PasswordMaxLength):
		return userErr{
			Code: v1.ErrCodeInvalidPassword,
			Context: fmt.Sprintf("password exceedes the max length of %v characters",
				s.PasswordMaxLength),
		}
	}
	return nil
}

// validateContactInfo validates that contact info data meets the plugin
// requirements.
func validateContactInfo(s settings, c contactInfo) error {
	_, ok := s.ContactTypes[c.Type]
	if !ok {
		return userErr{
			Code:    v1.ErrCodeInvalidContactInfo,
			Context: fmt.Sprintf("%v contact type is invalid", c.Type),
		}
	}

	switch c.Type {
	case contactTypeEmail:
		return validateEmail(c.Contact)
	}

	// Should not be possible
	return errors.Errorf("invalid contact type")
}

var (
	// emailRegexp contains the regular expression that is used to validate an
	// email address.
	emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

// validateEmail validates that an email address is sane.
func validateEmail(email string) error {
	if !emailRegexp.MatchString(email) {
		return userErr{
			Code:    v1.ErrCodeInvalidContactInfo,
			Context: "email address is invalid",
		}
	}
	return nil
}

// validUserID returns whether the provided string is a valid uuid.
func validUserID(userID string) bool {
	_, err := uuid.Parse(userID)
	return err == nil
}
