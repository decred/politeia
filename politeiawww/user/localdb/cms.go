// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"strings"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	cmsUserPrefix = "cmswww"
)

// isCMSUserRecord returns true if the given key is a cms user record,
// and false otherwise. This is helpful when iterating the user records
// because the DB contains some non-user records.
func isCMSUserRecord(key string) bool {
	return strings.HasPrefix(key, cmsUserPrefix)
}

// cmdNewCMSUser inserts a new CMSUser record into the database.
func (l *localdb) cmdNewCMSUser(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeNewCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	if l.shutdown {
		return "", user.ErrShutdown
	}

	log.Debugf("cmdNewCMSUser: %v", nu.Email)

	// Create a new User record
	u := user.User{
		Email:                     nu.Email,
		Username:                  nu.Username,
		NewUserVerificationToken:  nu.NewUserVerificationToken,
		NewUserVerificationExpiry: nu.NewUserVerificationExpiry,
	}
	err = l.UserNew(u)
	if err != nil {
		return "", err
	}

	// Get user that we just created to get the ID and other User stuff set
	setUser, err := l.UserGet(nu.Email)
	if err != nil {
		return "", err
	}

	l.Lock()
	defer l.Unlock()

	cmsUser := user.CMSUser{
		User:           *setUser,
		ContractorType: nu.ContractorType,
	}
	key := []byte(cmsUserPrefix + cmsUser.Email)

	// Make sure cms user does not exist
	ok, err := l.userdb.Has(key, nil)
	if err != nil {
		return "", err
	} else if ok {
		return "", user.ErrUserExists
	}

	cmsPayload, err := user.EncodeCMSUser(cmsUser)
	if err != nil {
		return "", err
	}

	err = l.userdb.Put(key, cmsPayload, nil)
	if err != nil {
		return "", err
	}

	// Prepare reply
	var nur user.NewCMSUserReply
	reply, err := user.EncodeNewCMSUserReply(nur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// updateCMSUser updates an existing CMSUser record with the provided user
// info.
func (l *localdb) updateCMSUser(nu user.UpdateCMSUser) error {
	if l.shutdown {
		return user.ErrShutdown
	}

	log.Debugf("updateCMSUser: %v", nu.ID)

	// Get user that we just created to get the ID and other User stuff set
	setUser, err := l.UserGetById(nu.ID)
	if err != nil {
		return err
	}

	l.Lock()
	defer l.Unlock()

	u := user.CMSUser{
		User:               *setUser,
		Domain:             nu.Domain,
		ContractorName:     nu.ContractorName,
		ContractorType:     nu.ContractorType,
		ContractorContact:  nu.ContractorContact,
		ContractorLocation: nu.ContractorLocation,
		GitHubName:         nu.GitHubName,
		MatrixName:         nu.MatrixName,
		ProposalsOwned:     nu.ProposalsOwned,
		SupervisorUserIDs:  nu.SupervisorUserIDs,
	}
	key := []byte(cmsUserPrefix + setUser.Email)

	// Make sure user already exists
	exists, err := l.userdb.Has(key, nil)
	if err != nil {
		return err
	} else if !exists {
		return user.ErrUserNotFound
	}

	payload, err := user.EncodeCMSUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put(key, payload, nil)
}

// cmdUpdateCMSUser updates an existing CMSUser record in the database.
func (l *localdb) cmdUpdateCMSUser(payload string) (string, error) {
	// Decode payload
	uu, err := user.DecodeUpdateCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	err = l.updateCMSUser(*uu)
	if err != nil {
		return "", err
	}

	// Prepare reply
	var uur user.UpdateCMSUserReply
	reply, err := user.EncodeUpdateCMSUserReply(uur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// cmdCMSUserByID returns the user information for a given user ID.
func (l *localdb) cmdCMSUserByID(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return "", user.ErrShutdown
	}

	log.Debugf("cmsCMSUserById")

	iter := l.userdb.NewIterator(util.BytesPrefix([]byte(cmsUserPrefix)), nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isCMSUserRecord(string(key)) {
			continue
		}

		u, err := user.DecodeCMSUser(value)
		if err != nil {
			return "", err
		}

		if u.ID.String() == p.ID {
			r := user.CMSUserByIDReply{
				User: u,
			}
			reply, err := user.EncodeCMSUserByIDReply(r)
			if err != nil {
				return "", err
			}

			return string(reply), nil
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return "", iter.Error()
	}

	return "", user.ErrUserNotFound
}

// Exec executes a cms plugin command.
func (l *localdb) cmsPluginExec(cmd, payload string) (string, error) {
	switch cmd {
	case user.CmdNewCMSUser:
		return l.cmdNewCMSUser(payload)
	case user.CmdUpdateCMSUser:
		return l.cmdUpdateCMSUser(payload)
	case user.CmdCMSUserByID:
		return l.cmdCMSUserByID(payload)
	default:
		return "", user.ErrInvalidPluginCmd
	}
}
