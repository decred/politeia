package plugin

import "errors"

var (
	// ErrInvalidPluginCmd is emitted when an invalid plugin command is
	// used.
	ErrInvalidPluginCmd = errors.New("invalid plugin command")
)

type Plugin interface {
	Setup() error
	Cmd(id, payload string) (string, error)
}
