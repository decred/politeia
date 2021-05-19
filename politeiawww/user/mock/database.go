// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mock

import (
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"sync"
)

// Ensure, that DatabaseMock does implement user.Database.
// If this is not the case, regenerate this file with moq.
var _ user.Database = &DatabaseMock{}

// DatabaseMock is a mock implementation of user.Database.
//
//     func TestSomethingThatUsesDatabase(t *testing.T) {
//
//         // make and configure a mocked user.Database
//         mockedDatabase := &DatabaseMock{
//             AllUsersFunc: func(callbackFn func(u *user.User)) error {
// 	               panic("mock out the AllUsers method")
//             },
//             CloseFunc: func() error {
// 	               panic("mock out the Close method")
//             },
//             EmailHistoriesGet24hFunc: func(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory24h, error) {
// 	               panic("mock out the EmailHistoriesGet24h method")
//             },
//             EmailHistoriesSave24hFunc: func(histories map[uuid.UUID]user.EmailHistory24h) error {
// 	               panic("mock out the EmailHistoriesSave24h method")
//             },
//             PluginExecFunc: func(in1 user.PluginCommand) (*user.PluginCommandReply, error) {
// 	               panic("mock out the PluginExec method")
//             },
//             RegisterPluginFunc: func(in1 user.Plugin) error {
// 	               panic("mock out the RegisterPlugin method")
//             },
//             SessionDeleteByIDFunc: func(sessionID string) error {
// 	               panic("mock out the SessionDeleteByID method")
//             },
//             SessionGetByIDFunc: func(sessionID string) (*user.Session, error) {
// 	               panic("mock out the SessionGetByID method")
//             },
//             SessionSaveFunc: func(in1 user.Session) error {
// 	               panic("mock out the SessionSave method")
//             },
//             SessionsDeleteByUserIDFunc: func(id uuid.UUID, exemptSessionIDs []string) error {
// 	               panic("mock out the SessionsDeleteByUserID method")
//             },
//             UserGetByIdFunc: func(in1 uuid.UUID) (*user.User, error) {
// 	               panic("mock out the UserGetById method")
//             },
//             UserGetByPubKeyFunc: func(in1 string) (*user.User, error) {
// 	               panic("mock out the UserGetByPubKey method")
//             },
//             UserGetByUsernameFunc: func(in1 string) (*user.User, error) {
// 	               panic("mock out the UserGetByUsername method")
//             },
//             UserNewFunc: func(in1 user.User) error {
// 	               panic("mock out the UserNew method")
//             },
//             UserUpdateFunc: func(in1 user.User) error {
// 	               panic("mock out the UserUpdate method")
//             },
//             UsersGetByPubKeyFunc: func(pubKeys []string) (map[string]user.User, error) {
// 	               panic("mock out the UsersGetByPubKey method")
//             },
//         }
//
//         // use mockedDatabase in code that requires user.Database
//         // and then make assertions.
//
//     }
type DatabaseMock struct {
	// AllUsersFunc mocks the AllUsers method.
	AllUsersFunc func(callbackFn func(u *user.User)) error

	// CloseFunc mocks the Close method.
	CloseFunc func() error

	// EmailHistoriesGet24hFunc mocks the EmailHistoriesGet24h method.
	EmailHistoriesGet24hFunc func(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory24h, error)

	// EmailHistoriesSave24hFunc mocks the EmailHistoriesSave24h method.
	EmailHistoriesSave24hFunc func(histories map[uuid.UUID]user.EmailHistory24h) error

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

	// calls tracks calls to the methods.
	calls struct {
		// AllUsers holds details about calls to the AllUsers method.
		AllUsers []struct {
			// CallbackFn is the callbackFn argument value.
			CallbackFn func(u *user.User)
		}
		// Close holds details about calls to the Close method.
		Close []struct {
		}
		// EmailHistoriesGet24h holds details about calls to the EmailHistoriesGet24h method.
		EmailHistoriesGet24h []struct {
			// Recipients is the recipients argument value.
			Recipients []uuid.UUID
		}
		// EmailHistoriesSave24h holds details about calls to the EmailHistoriesSave24h method.
		EmailHistoriesSave24h []struct {
			// Histories is the histories argument value.
			Histories map[uuid.UUID]user.EmailHistory24h
		}
		// PluginExec holds details about calls to the PluginExec method.
		PluginExec []struct {
			// In1 is the in1 argument value.
			In1 user.PluginCommand
		}
		// RegisterPlugin holds details about calls to the RegisterPlugin method.
		RegisterPlugin []struct {
			// In1 is the in1 argument value.
			In1 user.Plugin
		}
		// SessionDeleteByID holds details about calls to the SessionDeleteByID method.
		SessionDeleteByID []struct {
			// SessionID is the sessionID argument value.
			SessionID string
		}
		// SessionGetByID holds details about calls to the SessionGetByID method.
		SessionGetByID []struct {
			// SessionID is the sessionID argument value.
			SessionID string
		}
		// SessionSave holds details about calls to the SessionSave method.
		SessionSave []struct {
			// In1 is the in1 argument value.
			In1 user.Session
		}
		// SessionsDeleteByUserID holds details about calls to the SessionsDeleteByUserID method.
		SessionsDeleteByUserID []struct {
			// ID is the id argument value.
			ID uuid.UUID
			// ExemptSessionIDs is the exemptSessionIDs argument value.
			ExemptSessionIDs []string
		}
		// UserGetById holds details about calls to the UserGetById method.
		UserGetById []struct {
			// In1 is the in1 argument value.
			In1 uuid.UUID
		}
		// UserGetByPubKey holds details about calls to the UserGetByPubKey method.
		UserGetByPubKey []struct {
			// In1 is the in1 argument value.
			In1 string
		}
		// UserGetByUsername holds details about calls to the UserGetByUsername method.
		UserGetByUsername []struct {
			// In1 is the in1 argument value.
			In1 string
		}
		// UserNew holds details about calls to the UserNew method.
		UserNew []struct {
			// In1 is the in1 argument value.
			In1 user.User
		}
		// UserUpdate holds details about calls to the UserUpdate method.
		UserUpdate []struct {
			// In1 is the in1 argument value.
			In1 user.User
		}
		// UsersGetByPubKey holds details about calls to the UsersGetByPubKey method.
		UsersGetByPubKey []struct {
			// PubKeys is the pubKeys argument value.
			PubKeys []string
		}
	}
	lockAllUsers               sync.RWMutex
	lockClose                  sync.RWMutex
	lockEmailHistoriesGet24h   sync.RWMutex
	lockEmailHistoriesSave24h  sync.RWMutex
	lockPluginExec             sync.RWMutex
	lockRegisterPlugin         sync.RWMutex
	lockSessionDeleteByID      sync.RWMutex
	lockSessionGetByID         sync.RWMutex
	lockSessionSave            sync.RWMutex
	lockSessionsDeleteByUserID sync.RWMutex
	lockUserGetById            sync.RWMutex
	lockUserGetByPubKey        sync.RWMutex
	lockUserGetByUsername      sync.RWMutex
	lockUserNew                sync.RWMutex
	lockUserUpdate             sync.RWMutex
	lockUsersGetByPubKey       sync.RWMutex
}

// AllUsers calls AllUsersFunc.
func (mock *DatabaseMock) AllUsers(callbackFn func(u *user.User)) error {
	if mock.AllUsersFunc == nil {
		panic("DatabaseMock.AllUsersFunc: method is nil but Database.AllUsers was just called")
	}
	callInfo := struct {
		CallbackFn func(u *user.User)
	}{
		CallbackFn: callbackFn,
	}
	mock.lockAllUsers.Lock()
	mock.calls.AllUsers = append(mock.calls.AllUsers, callInfo)
	mock.lockAllUsers.Unlock()
	return mock.AllUsersFunc(callbackFn)
}

// AllUsersCalls gets all the calls that were made to AllUsers.
// Check the length with:
//     len(mockedDatabase.AllUsersCalls())
func (mock *DatabaseMock) AllUsersCalls() []struct {
	CallbackFn func(u *user.User)
} {
	var calls []struct {
		CallbackFn func(u *user.User)
	}
	mock.lockAllUsers.RLock()
	calls = mock.calls.AllUsers
	mock.lockAllUsers.RUnlock()
	return calls
}

// Close calls CloseFunc.
func (mock *DatabaseMock) Close() error {
	if mock.CloseFunc == nil {
		panic("DatabaseMock.CloseFunc: method is nil but Database.Close was just called")
	}
	callInfo := struct {
	}{}
	mock.lockClose.Lock()
	mock.calls.Close = append(mock.calls.Close, callInfo)
	mock.lockClose.Unlock()
	return mock.CloseFunc()
}

// CloseCalls gets all the calls that were made to Close.
// Check the length with:
//     len(mockedDatabase.CloseCalls())
func (mock *DatabaseMock) CloseCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockClose.RLock()
	calls = mock.calls.Close
	mock.lockClose.RUnlock()
	return calls
}

// EmailHistoriesGet24h calls EmailHistoriesGet24hFunc.
func (mock *DatabaseMock) EmailHistoriesGet24h(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory24h, error) {
	if mock.EmailHistoriesGet24hFunc == nil {
		panic("DatabaseMock.EmailHistoriesGet24hFunc: method is nil but Database.EmailHistoriesGet24h was just called")
	}
	callInfo := struct {
		Recipients []uuid.UUID
	}{
		Recipients: recipients,
	}
	mock.lockEmailHistoriesGet24h.Lock()
	mock.calls.EmailHistoriesGet24h = append(mock.calls.EmailHistoriesGet24h, callInfo)
	mock.lockEmailHistoriesGet24h.Unlock()
	return mock.EmailHistoriesGet24hFunc(recipients)
}

// EmailHistoriesGet24hCalls gets all the calls that were made to EmailHistoriesGet24h.
// Check the length with:
//     len(mockedDatabase.EmailHistoriesGet24hCalls())
func (mock *DatabaseMock) EmailHistoriesGet24hCalls() []struct {
	Recipients []uuid.UUID
} {
	var calls []struct {
		Recipients []uuid.UUID
	}
	mock.lockEmailHistoriesGet24h.RLock()
	calls = mock.calls.EmailHistoriesGet24h
	mock.lockEmailHistoriesGet24h.RUnlock()
	return calls
}

// EmailHistoriesSave24h calls EmailHistoriesSave24hFunc.
func (mock *DatabaseMock) EmailHistoriesSave24h(histories map[uuid.UUID]user.EmailHistory24h) error {
	if mock.EmailHistoriesSave24hFunc == nil {
		panic("DatabaseMock.EmailHistoriesSave24hFunc: method is nil but Database.EmailHistoriesSave24h was just called")
	}
	callInfo := struct {
		Histories map[uuid.UUID]user.EmailHistory24h
	}{
		Histories: histories,
	}
	mock.lockEmailHistoriesSave24h.Lock()
	mock.calls.EmailHistoriesSave24h = append(mock.calls.EmailHistoriesSave24h, callInfo)
	mock.lockEmailHistoriesSave24h.Unlock()
	return mock.EmailHistoriesSave24hFunc(histories)
}

// EmailHistoriesSave24hCalls gets all the calls that were made to EmailHistoriesSave24h.
// Check the length with:
//     len(mockedDatabase.EmailHistoriesSave24hCalls())
func (mock *DatabaseMock) EmailHistoriesSave24hCalls() []struct {
	Histories map[uuid.UUID]user.EmailHistory24h
} {
	var calls []struct {
		Histories map[uuid.UUID]user.EmailHistory24h
	}
	mock.lockEmailHistoriesSave24h.RLock()
	calls = mock.calls.EmailHistoriesSave24h
	mock.lockEmailHistoriesSave24h.RUnlock()
	return calls
}

// PluginExec calls PluginExecFunc.
func (mock *DatabaseMock) PluginExec(in1 user.PluginCommand) (*user.PluginCommandReply, error) {
	if mock.PluginExecFunc == nil {
		panic("DatabaseMock.PluginExecFunc: method is nil but Database.PluginExec was just called")
	}
	callInfo := struct {
		In1 user.PluginCommand
	}{
		In1: in1,
	}
	mock.lockPluginExec.Lock()
	mock.calls.PluginExec = append(mock.calls.PluginExec, callInfo)
	mock.lockPluginExec.Unlock()
	return mock.PluginExecFunc(in1)
}

// PluginExecCalls gets all the calls that were made to PluginExec.
// Check the length with:
//     len(mockedDatabase.PluginExecCalls())
func (mock *DatabaseMock) PluginExecCalls() []struct {
	In1 user.PluginCommand
} {
	var calls []struct {
		In1 user.PluginCommand
	}
	mock.lockPluginExec.RLock()
	calls = mock.calls.PluginExec
	mock.lockPluginExec.RUnlock()
	return calls
}

// RegisterPlugin calls RegisterPluginFunc.
func (mock *DatabaseMock) RegisterPlugin(in1 user.Plugin) error {
	if mock.RegisterPluginFunc == nil {
		panic("DatabaseMock.RegisterPluginFunc: method is nil but Database.RegisterPlugin was just called")
	}
	callInfo := struct {
		In1 user.Plugin
	}{
		In1: in1,
	}
	mock.lockRegisterPlugin.Lock()
	mock.calls.RegisterPlugin = append(mock.calls.RegisterPlugin, callInfo)
	mock.lockRegisterPlugin.Unlock()
	return mock.RegisterPluginFunc(in1)
}

// RegisterPluginCalls gets all the calls that were made to RegisterPlugin.
// Check the length with:
//     len(mockedDatabase.RegisterPluginCalls())
func (mock *DatabaseMock) RegisterPluginCalls() []struct {
	In1 user.Plugin
} {
	var calls []struct {
		In1 user.Plugin
	}
	mock.lockRegisterPlugin.RLock()
	calls = mock.calls.RegisterPlugin
	mock.lockRegisterPlugin.RUnlock()
	return calls
}

// SessionDeleteByID calls SessionDeleteByIDFunc.
func (mock *DatabaseMock) SessionDeleteByID(sessionID string) error {
	if mock.SessionDeleteByIDFunc == nil {
		panic("DatabaseMock.SessionDeleteByIDFunc: method is nil but Database.SessionDeleteByID was just called")
	}
	callInfo := struct {
		SessionID string
	}{
		SessionID: sessionID,
	}
	mock.lockSessionDeleteByID.Lock()
	mock.calls.SessionDeleteByID = append(mock.calls.SessionDeleteByID, callInfo)
	mock.lockSessionDeleteByID.Unlock()
	return mock.SessionDeleteByIDFunc(sessionID)
}

// SessionDeleteByIDCalls gets all the calls that were made to SessionDeleteByID.
// Check the length with:
//     len(mockedDatabase.SessionDeleteByIDCalls())
func (mock *DatabaseMock) SessionDeleteByIDCalls() []struct {
	SessionID string
} {
	var calls []struct {
		SessionID string
	}
	mock.lockSessionDeleteByID.RLock()
	calls = mock.calls.SessionDeleteByID
	mock.lockSessionDeleteByID.RUnlock()
	return calls
}

// SessionGetByID calls SessionGetByIDFunc.
func (mock *DatabaseMock) SessionGetByID(sessionID string) (*user.Session, error) {
	if mock.SessionGetByIDFunc == nil {
		panic("DatabaseMock.SessionGetByIDFunc: method is nil but Database.SessionGetByID was just called")
	}
	callInfo := struct {
		SessionID string
	}{
		SessionID: sessionID,
	}
	mock.lockSessionGetByID.Lock()
	mock.calls.SessionGetByID = append(mock.calls.SessionGetByID, callInfo)
	mock.lockSessionGetByID.Unlock()
	return mock.SessionGetByIDFunc(sessionID)
}

// SessionGetByIDCalls gets all the calls that were made to SessionGetByID.
// Check the length with:
//     len(mockedDatabase.SessionGetByIDCalls())
func (mock *DatabaseMock) SessionGetByIDCalls() []struct {
	SessionID string
} {
	var calls []struct {
		SessionID string
	}
	mock.lockSessionGetByID.RLock()
	calls = mock.calls.SessionGetByID
	mock.lockSessionGetByID.RUnlock()
	return calls
}

// SessionSave calls SessionSaveFunc.
func (mock *DatabaseMock) SessionSave(in1 user.Session) error {
	if mock.SessionSaveFunc == nil {
		panic("DatabaseMock.SessionSaveFunc: method is nil but Database.SessionSave was just called")
	}
	callInfo := struct {
		In1 user.Session
	}{
		In1: in1,
	}
	mock.lockSessionSave.Lock()
	mock.calls.SessionSave = append(mock.calls.SessionSave, callInfo)
	mock.lockSessionSave.Unlock()
	return mock.SessionSaveFunc(in1)
}

// SessionSaveCalls gets all the calls that were made to SessionSave.
// Check the length with:
//     len(mockedDatabase.SessionSaveCalls())
func (mock *DatabaseMock) SessionSaveCalls() []struct {
	In1 user.Session
} {
	var calls []struct {
		In1 user.Session
	}
	mock.lockSessionSave.RLock()
	calls = mock.calls.SessionSave
	mock.lockSessionSave.RUnlock()
	return calls
}

// SessionsDeleteByUserID calls SessionsDeleteByUserIDFunc.
func (mock *DatabaseMock) SessionsDeleteByUserID(id uuid.UUID, exemptSessionIDs []string) error {
	if mock.SessionsDeleteByUserIDFunc == nil {
		panic("DatabaseMock.SessionsDeleteByUserIDFunc: method is nil but Database.SessionsDeleteByUserID was just called")
	}
	callInfo := struct {
		ID               uuid.UUID
		ExemptSessionIDs []string
	}{
		ID:               id,
		ExemptSessionIDs: exemptSessionIDs,
	}
	mock.lockSessionsDeleteByUserID.Lock()
	mock.calls.SessionsDeleteByUserID = append(mock.calls.SessionsDeleteByUserID, callInfo)
	mock.lockSessionsDeleteByUserID.Unlock()
	return mock.SessionsDeleteByUserIDFunc(id, exemptSessionIDs)
}

// SessionsDeleteByUserIDCalls gets all the calls that were made to SessionsDeleteByUserID.
// Check the length with:
//     len(mockedDatabase.SessionsDeleteByUserIDCalls())
func (mock *DatabaseMock) SessionsDeleteByUserIDCalls() []struct {
	ID               uuid.UUID
	ExemptSessionIDs []string
} {
	var calls []struct {
		ID               uuid.UUID
		ExemptSessionIDs []string
	}
	mock.lockSessionsDeleteByUserID.RLock()
	calls = mock.calls.SessionsDeleteByUserID
	mock.lockSessionsDeleteByUserID.RUnlock()
	return calls
}

// UserGetById calls UserGetByIdFunc.
func (mock *DatabaseMock) UserGetById(in1 uuid.UUID) (*user.User, error) {
	if mock.UserGetByIdFunc == nil {
		panic("DatabaseMock.UserGetByIdFunc: method is nil but Database.UserGetById was just called")
	}
	callInfo := struct {
		In1 uuid.UUID
	}{
		In1: in1,
	}
	mock.lockUserGetById.Lock()
	mock.calls.UserGetById = append(mock.calls.UserGetById, callInfo)
	mock.lockUserGetById.Unlock()
	return mock.UserGetByIdFunc(in1)
}

// UserGetByIdCalls gets all the calls that were made to UserGetById.
// Check the length with:
//     len(mockedDatabase.UserGetByIdCalls())
func (mock *DatabaseMock) UserGetByIdCalls() []struct {
	In1 uuid.UUID
} {
	var calls []struct {
		In1 uuid.UUID
	}
	mock.lockUserGetById.RLock()
	calls = mock.calls.UserGetById
	mock.lockUserGetById.RUnlock()
	return calls
}

// UserGetByPubKey calls UserGetByPubKeyFunc.
func (mock *DatabaseMock) UserGetByPubKey(in1 string) (*user.User, error) {
	if mock.UserGetByPubKeyFunc == nil {
		panic("DatabaseMock.UserGetByPubKeyFunc: method is nil but Database.UserGetByPubKey was just called")
	}
	callInfo := struct {
		In1 string
	}{
		In1: in1,
	}
	mock.lockUserGetByPubKey.Lock()
	mock.calls.UserGetByPubKey = append(mock.calls.UserGetByPubKey, callInfo)
	mock.lockUserGetByPubKey.Unlock()
	return mock.UserGetByPubKeyFunc(in1)
}

// UserGetByPubKeyCalls gets all the calls that were made to UserGetByPubKey.
// Check the length with:
//     len(mockedDatabase.UserGetByPubKeyCalls())
func (mock *DatabaseMock) UserGetByPubKeyCalls() []struct {
	In1 string
} {
	var calls []struct {
		In1 string
	}
	mock.lockUserGetByPubKey.RLock()
	calls = mock.calls.UserGetByPubKey
	mock.lockUserGetByPubKey.RUnlock()
	return calls
}

// UserGetByUsername calls UserGetByUsernameFunc.
func (mock *DatabaseMock) UserGetByUsername(in1 string) (*user.User, error) {
	if mock.UserGetByUsernameFunc == nil {
		panic("DatabaseMock.UserGetByUsernameFunc: method is nil but Database.UserGetByUsername was just called")
	}
	callInfo := struct {
		In1 string
	}{
		In1: in1,
	}
	mock.lockUserGetByUsername.Lock()
	mock.calls.UserGetByUsername = append(mock.calls.UserGetByUsername, callInfo)
	mock.lockUserGetByUsername.Unlock()
	return mock.UserGetByUsernameFunc(in1)
}

// UserGetByUsernameCalls gets all the calls that were made to UserGetByUsername.
// Check the length with:
//     len(mockedDatabase.UserGetByUsernameCalls())
func (mock *DatabaseMock) UserGetByUsernameCalls() []struct {
	In1 string
} {
	var calls []struct {
		In1 string
	}
	mock.lockUserGetByUsername.RLock()
	calls = mock.calls.UserGetByUsername
	mock.lockUserGetByUsername.RUnlock()
	return calls
}

// UserNew calls UserNewFunc.
func (mock *DatabaseMock) UserNew(in1 user.User) error {
	if mock.UserNewFunc == nil {
		panic("DatabaseMock.UserNewFunc: method is nil but Database.UserNew was just called")
	}
	callInfo := struct {
		In1 user.User
	}{
		In1: in1,
	}
	mock.lockUserNew.Lock()
	mock.calls.UserNew = append(mock.calls.UserNew, callInfo)
	mock.lockUserNew.Unlock()
	return mock.UserNewFunc(in1)
}

// UserNewCalls gets all the calls that were made to UserNew.
// Check the length with:
//     len(mockedDatabase.UserNewCalls())
func (mock *DatabaseMock) UserNewCalls() []struct {
	In1 user.User
} {
	var calls []struct {
		In1 user.User
	}
	mock.lockUserNew.RLock()
	calls = mock.calls.UserNew
	mock.lockUserNew.RUnlock()
	return calls
}

// UserUpdate calls UserUpdateFunc.
func (mock *DatabaseMock) UserUpdate(in1 user.User) error {
	if mock.UserUpdateFunc == nil {
		panic("DatabaseMock.UserUpdateFunc: method is nil but Database.UserUpdate was just called")
	}
	callInfo := struct {
		In1 user.User
	}{
		In1: in1,
	}
	mock.lockUserUpdate.Lock()
	mock.calls.UserUpdate = append(mock.calls.UserUpdate, callInfo)
	mock.lockUserUpdate.Unlock()
	return mock.UserUpdateFunc(in1)
}

// UserUpdateCalls gets all the calls that were made to UserUpdate.
// Check the length with:
//     len(mockedDatabase.UserUpdateCalls())
func (mock *DatabaseMock) UserUpdateCalls() []struct {
	In1 user.User
} {
	var calls []struct {
		In1 user.User
	}
	mock.lockUserUpdate.RLock()
	calls = mock.calls.UserUpdate
	mock.lockUserUpdate.RUnlock()
	return calls
}

// UsersGetByPubKey calls UsersGetByPubKeyFunc.
func (mock *DatabaseMock) UsersGetByPubKey(pubKeys []string) (map[string]user.User, error) {
	if mock.UsersGetByPubKeyFunc == nil {
		panic("DatabaseMock.UsersGetByPubKeyFunc: method is nil but Database.UsersGetByPubKey was just called")
	}
	callInfo := struct {
		PubKeys []string
	}{
		PubKeys: pubKeys,
	}
	mock.lockUsersGetByPubKey.Lock()
	mock.calls.UsersGetByPubKey = append(mock.calls.UsersGetByPubKey, callInfo)
	mock.lockUsersGetByPubKey.Unlock()
	return mock.UsersGetByPubKeyFunc(pubKeys)
}

// UsersGetByPubKeyCalls gets all the calls that were made to UsersGetByPubKey.
// Check the length with:
//     len(mockedDatabase.UsersGetByPubKeyCalls())
func (mock *DatabaseMock) UsersGetByPubKeyCalls() []struct {
	PubKeys []string
} {
	var calls []struct {
		PubKeys []string
	}
	mock.lockUsersGetByPubKey.RLock()
	calls = mock.calls.UsersGetByPubKey
	mock.lockUsersGetByPubKey.RUnlock()
	return calls
}
