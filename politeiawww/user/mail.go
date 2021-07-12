package user

import (
	"encoding/json"
)

// MailerDB describes the interface used to interact with the email histories
// table from the user database, used by the mail client.
type MailerDB interface {
	// Create or update users email histories
	EmailHistoriesSave(histories map[string]EmailHistory) error

	// Return a map of user ids to its email history
	EmailHistoriesGet(users []string) (map[string]EmailHistory, error)
}

// EmailHistory keeps track of the received emails by each user. This is
// used to rate limit the amount of emails an user can receive in a 24h
// time window. This was not stored in the user object in order to avoid
// race conditions on db calls, since our user db currently does not support
// transactions, and email notifications run in a separate goroutine. This
// workaround won't be necessary once the user layer gets rewritten.
type EmailHistory struct {
	Timestamps       []int64 `json:"timestamps"` // Received email UNIX ts
	LimitWarningSent bool    `json:"limitwarningsent"`
}

// VersionEmailHistory is the version of the EmailHistory struct.
const VersionEmailHistory uint32 = 1

// EncodeEmailHistory encodes EmailHistory into a JSON byte slice.
func EncodeEmailHistory(h EmailHistory) ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeEmailHistory decodes a JSON byte slice into a EmailHistory.
func DecodeEmailHistory(payload []byte) (*EmailHistory, error) {
	var h EmailHistory

	err := json.Unmarshal(payload, &h)
	if err != nil {
		return nil, err
	}

	return &h, nil
}
