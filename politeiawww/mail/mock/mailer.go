// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/google/uuid"
)

// Ensure, that MailerMock does implement Mailer.
var _ mail.Mailer = &MailerMock{}

// MailerMock is a mock implementation of Mailer.
type MailerMock struct {
	// IsEnabledFunc mocks the IsEnabled method.
	IsEnabledFunc func() bool

	// SendToFunc mocks the SendTo method.
	SendToFunc func(subject string, body string, recipients []string) error

	// SendToUsersFunc mocks the SendToUsers method.
	SendToUsersFunc func(subject string, body string, recipients map[uuid.UUID]string) error
}

// IsEnabled calls IsEnabledFunc.
func (mock *MailerMock) IsEnabled() bool {
	if mock.IsEnabledFunc == nil {
		panic("MailerMock.IsEnabledFunc: method is nil but Mailer.IsEnabled was just called")
	}
	return mock.IsEnabledFunc()
}

// SendTo calls SendToFunc.
func (mock *MailerMock) SendTo(subject string, body string, recipients []string) error {
	if mock.SendToFunc == nil {
		panic("MailerMock.SendToFunc: method is nil but Mailer.SendTo was just called")
	}
	return mock.SendToFunc(subject, body, recipients)
}

// SendToUsers calls SendToUsersFunc.
func (mock *MailerMock) SendToUsers(subject string, body string, recipients map[uuid.UUID]string) error {
	if mock.SendToUsersFunc == nil {
		panic("MailerMock.SendToUsersFunc: method is nil but Mailer.SendToUsers was just called")
	}
	return mock.SendToUsersFunc(subject, body, recipients)
}
