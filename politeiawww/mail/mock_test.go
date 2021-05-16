// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mail

import (
	"sync"
)

// Ensure, that MailerMock does implement Mailer.
// If this is not the case, regenerate this file with moq.
var _ Mailer = &MailerMock{}

// MailerMock is a mock implementation of Mailer.
//
//     func TestSomethingThatUsesMailer(t *testing.T) {
//
//         // make and configure a mocked Mailer
//         mockedMailer := &MailerMock{
//             IsEnabledFunc: func() bool {
// 	               panic("mock out the IsEnabled method")
//             },
//             SendToFunc: func(subject string, body string, recipients []string) error {
// 	               panic("mock out the SendTo method")
//             },
//         }
//
//         // use mockedMailer in code that requires Mailer
//         // and then make assertions.
//
//     }
type MailerMock struct {
	// IsEnabledFunc mocks the IsEnabled method.
	IsEnabledFunc func() bool

	// SendToFunc mocks the SendTo method.
	SendToFunc func(subject string, body string, recipients []string) error

	// calls tracks calls to the methods.
	calls struct {
		// IsEnabled holds details about calls to the IsEnabled method.
		IsEnabled []struct {
		}
		// SendTo holds details about calls to the SendTo method.
		SendTo []struct {
			// Subject is the subject argument value.
			Subject string
			// Body is the body argument value.
			Body string
			// Recipients is the recipients argument value.
			Recipients []string
		}
	}
	lockIsEnabled sync.RWMutex
	lockSendTo    sync.RWMutex
}

// IsEnabled calls IsEnabledFunc.
func (mock *MailerMock) IsEnabled() bool {
	if mock.IsEnabledFunc == nil {
		panic("MailerMock.IsEnabledFunc: method is nil but Mailer.IsEnabled was just called")
	}
	callInfo := struct {
	}{}
	mock.lockIsEnabled.Lock()
	mock.calls.IsEnabled = append(mock.calls.IsEnabled, callInfo)
	mock.lockIsEnabled.Unlock()
	return mock.IsEnabledFunc()
}

// IsEnabledCalls gets all the calls that were made to IsEnabled.
// Check the length with:
//     len(mockedMailer.IsEnabledCalls())
func (mock *MailerMock) IsEnabledCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockIsEnabled.RLock()
	calls = mock.calls.IsEnabled
	mock.lockIsEnabled.RUnlock()
	return calls
}

// SendTo calls SendToFunc.
func (mock *MailerMock) SendTo(subject string, body string, recipients []string) error {
	if mock.SendToFunc == nil {
		panic("MailerMock.SendToFunc: method is nil but Mailer.SendTo was just called")
	}
	callInfo := struct {
		Subject    string
		Body       string
		Recipients []string
	}{
		Subject:    subject,
		Body:       body,
		Recipients: recipients,
	}
	mock.lockSendTo.Lock()
	mock.calls.SendTo = append(mock.calls.SendTo, callInfo)
	mock.lockSendTo.Unlock()
	return mock.SendToFunc(subject, body, recipients)
}

// SendToCalls gets all the calls that were made to SendTo.
// Check the length with:
//     len(mockedMailer.SendToCalls())
func (mock *MailerMock) SendToCalls() []struct {
	Subject    string
	Body       string
	Recipients []string
} {
	var calls []struct {
		Subject    string
		Body       string
		Recipients []string
	}
	mock.lockSendTo.RLock()
	calls = mock.calls.SendTo
	mock.lockSendTo.RUnlock()
	return calls
}
