// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Ensure, that DatabaseMock does implement user.Database.
var _ user.Database = &DatabaseMock{}

// DatabaseMock is a mock implementation of user.Database.
type DatabaseMock struct {
	// AllUsersFunc mocks the AllUsers method.
	AllUsersFunc func(callbackFn func(u *user.User)) error

	// CloseFunc mocks the Close method.
	CloseFunc func() error

	// EmailHistoriesGetFunc mocks the EmailHistoriesGet method.
	EmailHistoriesGetFunc func(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory, error)

	// EmailHistoriesSaveFunc mocks the EmailHistoriesSave method.
	EmailHistoriesSaveFunc func(histories map[uuid.UUID]user.EmailHistory) error

	// PluginExecFunc mocks the PluginExec method.
	PluginExecFunc func(in1 user.PluginCommand) (*user.PluginCommandReply, error)

	// RegisterPluginFunc mocks the RegisterPlugin method.
	RegisterPluginFunc func(in1 user.Plugin) error

	// SessionDeleteByIDFunc mocks the SessionDeleteByID method.
	SessionDeleteByIDFunc func(sessionID string) error

	// SessionGetByIDFunc mocks the SessionGetByID method.
	SessionGetByIDFunc func(sessionID string) (*user.Session, error)

	// SessionSaveFunc mocks the SessionSave method.
	SessionSaveFunc func(in1 user.Session) error

	// SessionsDeleteByUserIDFunc mocks the SessionsDeleteByUserID method.
	SessionsDeleteByUserIDFunc func(id uuid.UUID, exemptSessionIDs []string) error

	// UserGetByIdFunc mocks the UserGetById method.
	UserGetByIdFunc func(in1 uuid.UUID) (*user.User, error)

	// UserGetByPubKeyFunc mocks the UserGetByPubKey method.
	UserGetByPubKeyFunc func(in1 string) (*user.User, error)

	// UserGetByUsernameFunc mocks the UserGetByUsername method.
	UserGetByUsernameFunc func(in1 string) (*user.User, error)

	// UserNewFunc mocks the UserNew method.
	UserNewFunc func(in1 user.User) error

	// UserUpdateFunc mocks the UserUpdate method.
	UserUpdateFunc func(in1 user.User) error

	// UsersGetByPubKeyFunc mocks the UsersGetByPubKey method.
	UsersGetByPubKeyFunc func(pubKeys []string) (map[string]user.User, error)
}

// AllUsers calls AllUsersFunc.
func (mock *DatabaseMock) AllUsers(callbackFn func(u *user.User)) error {
	if mock.AllUsersFunc == nil {
		panic("DatabaseMock.AllUsersFunc: method is nil but Database.AllUsers was just called")
	}
	return mock.AllUsersFunc(callbackFn)
}

// Close calls CloseFunc.
func (mock *DatabaseMock) Close() error {
	if mock.CloseFunc == nil {
		panic("DatabaseMock.CloseFunc: method is nil but Database.Close was just called")
	}
	return mock.CloseFunc()
}

// EmailHistoriesGet calls EmailHistoriesGetFunc.
func (mock *DatabaseMock) EmailHistoriesGet(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory, error) {
	if mock.EmailHistoriesGetFunc == nil {
		panic("DatabaseMock.EmailHistoriesGetFunc: method is nil but Database.EmailHistoriesGet was just called")
	}
	return mock.EmailHistoriesGetFunc(recipients)
}

// EmailHistoriesSave calls EmailHistoriesSaveFunc.
func (mock *DatabaseMock) EmailHistoriesSave(histories map[uuid.UUID]user.EmailHistory) error {
	if mock.EmailHistoriesSaveFunc == nil {
		panic("DatabaseMock.EmailHistoriesSaveFunc: method is nil but Database.EmailHistoriesSave was just called")
	}
	return mock.EmailHistoriesSaveFunc(histories)
}

// PluginExec calls PluginExecFunc.
func (mock *DatabaseMock) PluginExec(in1 user.PluginCommand) (*user.PluginCommandReply, error) {
	if mock.PluginExecFunc == nil {
		panic("DatabaseMock.PluginExecFunc: method is nil but Database.PluginExec was just called")
	}
	return mock.PluginExecFunc(in1)
}

// RegisterPlugin calls RegisterPluginFunc.
func (mock *DatabaseMock) RegisterPlugin(in1 user.Plugin) error {
	if mock.RegisterPluginFunc == nil {
		panic("DatabaseMock.RegisterPluginFunc: method is nil but Database.RegisterPlugin was just called")
	}
	return mock.RegisterPluginFunc(in1)
}

// SessionDeleteByID calls SessionDeleteByIDFunc.
func (mock *DatabaseMock) SessionDeleteByID(sessionID string) error {
	if mock.SessionDeleteByIDFunc == nil {
		panic("DatabaseMock.SessionDeleteByIDFunc: method is nil but Database.SessionDeleteByID was just called")
	}
	return mock.SessionDeleteByIDFunc(sessionID)
}

// SessionGetByID calls SessionGetByIDFunc.
func (mock *DatabaseMock) SessionGetByID(sessionID string) (*user.Session, error) {
	if mock.SessionGetByIDFunc == nil {
		panic("DatabaseMock.SessionGetByIDFunc: method is nil but Database.SessionGetByID was just called")
	}
	return mock.SessionGetByIDFunc(sessionID)
}

// SessionSave calls SessionSaveFunc.
func (mock *DatabaseMock) SessionSave(in1 user.Session) error {
	if mock.SessionSaveFunc == nil {
		panic("DatabaseMock.SessionSaveFunc: method is nil but Database.SessionSave was just called")
	}
	return mock.SessionSaveFunc(in1)
}

// SessionsDeleteByUserID calls SessionsDeleteByUserIDFunc.
func (mock *DatabaseMock) SessionsDeleteByUserID(id uuid.UUID, exemptSessionIDs []string) error {
	if mock.SessionsDeleteByUserIDFunc == nil {
		panic("DatabaseMock.SessionsDeleteByUserIDFunc: method is nil but Database.SessionsDeleteByUserID was just called")
	}
	return mock.SessionsDeleteByUserIDFunc(id, exemptSessionIDs)
}

// UserGetById calls UserGetByIdFunc.
func (mock *DatabaseMock) UserGetById(in1 uuid.UUID) (*user.User, error) {
	if mock.UserGetByIdFunc == nil {
		panic("DatabaseMock.UserGetByIdFunc: method is nil but Database.UserGetById was just called")
	}
	return mock.UserGetByIdFunc(in1)
}

// UserGetByPubKey calls UserGetByPubKeyFunc.
func (mock *DatabaseMock) UserGetByPubKey(in1 string) (*user.User, error) {
	if mock.UserGetByPubKeyFunc == nil {
		panic("DatabaseMock.UserGetByPubKeyFunc: method is nil but Database.UserGetByPubKey was just called")
	}
	return mock.UserGetByPubKeyFunc(in1)
}

// UserGetByUsername calls UserGetByUsernameFunc.
func (mock *DatabaseMock) UserGetByUsername(in1 string) (*user.User, error) {
	if mock.UserGetByUsernameFunc == nil {
		panic("DatabaseMock.UserGetByUsernameFunc: method is nil but Database.UserGetByUsername was just called")
	}
	return mock.UserGetByUsernameFunc(in1)
}

// UserNew calls UserNewFunc.
func (mock *DatabaseMock) UserNew(in1 user.User) error {
	if mock.UserNewFunc == nil {
		panic("DatabaseMock.UserNewFunc: method is nil but Database.UserNew was just called")
	}
	return mock.UserNewFunc(in1)
}

// UserUpdate calls UserUpdateFunc.
func (mock *DatabaseMock) UserUpdate(in1 user.User) error {
	if mock.UserUpdateFunc == nil {
		panic("DatabaseMock.UserUpdateFunc: method is nil but Database.UserUpdate was just called")
	}
	return mock.UserUpdateFunc(in1)
}

// UsersGetByPubKey calls UsersGetByPubKeyFunc.
func (mock *DatabaseMock) UsersGetByPubKey(pubKeys []string) (map[string]user.User, error) {
	if mock.UsersGetByPubKeyFunc == nil {
		panic("DatabaseMock.UsersGetByPubKeyFunc: method is nil but Database.UsersGetByPubKey was just called")
	}
	return mock.UsersGetByPubKeyFunc(pubKeys)
}
