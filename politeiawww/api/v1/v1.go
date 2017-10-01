package v1

import (
	"errors"
	"fmt"

	v1d "github.com/decred/politeia/politeiad/api/v1"
)

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteNewUser           = "/user/new"
	RouteVerifyNewUser     = "/user/verify"
	RouteLogin             = "/login"
	RouteLogout            = "/logout"
	RouteSecret            = "/secret"
	RouteAllVetted         = "/proposals/vetted"
	RouteAllUnvetted       = "/proposals/unvetted"
	RouteNewProposal       = "/proposals/new"
	RouteProposalDetails   = "/proposals/{token:[A-z0-9]{64}}"
	RouteSetProposalStatus = "/proposals/{token:[A-z0-9]{64}}/setstatus"
	RoutePolicy            = "/policy"

	// Size of verification token in bytes
	VerificationTokenSize = 32

	// Number of hours before the verification token expires
	VerificationExpiryHours = 48

	PolicyMaxImages    = 5
	PolicyMaxImageSize = 2048
	PolicyMaxMDs       = 1
	PolicyMaxMDSize    = 1024
)

var (
	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/v%v", PoliteiaWWWAPIVersion)

	// CookieSession is the cookie name that indicates that a user is
	// logged in.
	CookieSession = "session"

	// ErrInvalidEmailOrPassword is emitted when trying to log in.
	ErrInvalidEmailOrPassword = errors.New("invalid email or password")

	// ErrMissingProposalName is emitted when trying to submit a proposal
	// without a name.
	ErrMissingProposalName = errors.New("proposal missing name")

	// ErrMissingProposalDesc is emitted when trying to submit a proposal
	// without a description.
	ErrMissingProposalDesc = errors.New("proposal missing description")

	// ErrProposalNotFound is emitted when trying to fetch a proposal
	// that cannot be found with the given token.
	ErrProposalNotFound = errors.New("proposal not found")

	// ErrMaxMDsExceededPolicy is emitted when trying to submit a proposal
	// with a number of md files greater than the limit
	ErrMaxMDsExceededPolicy = errors.New("number of max md files exceeded")

	// ErrMaxImagesExceededPolicy is emitted when trying to submit a proposal
	// with a number of image files greater than the limit
	ErrMaxImagesExceededPolicy = errors.New("number of max image files exceeded")

	// ErrMaxMDSizeExceededPolicy is emitted when trying to submit a proposal
	// with an md file greater than the size limit
	ErrMaxMDSizeExceededPolicy = errors.New("max md file size exceeded")

	// ErrMaxImageSizeExceededPolicy is emitted when trying to submit a proposal
	// with an image file greater than the size limit
	ErrMaxImageSizeExceededPolicy = errors.New("max image file size exceeded")
)

// Version command is used to determine the version of the API this backend
// understands and additionally it provides the route to said API.
type Version struct {
	Version uint   `json:"version"` // politeia WWW API version
	Route   string `json:"route"`   // prefix to API calls
}

// NewUser is used to request that a new user be created within the db.
// If successful, the user will require verification before being able to login.
type NewUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// NewUserReply is used to reply to the NewUser command with
// the verification token.
type NewUserReply struct {
	VerificationToken string `json:"verificationtoken"`
}

// VerifyNewUser is used to perform verification for the user created through
// the NewUser command using the token provided in NewUserReply.
type VerifyNewUser struct {
	Email             string `json:"email"`
	VerificationToken string `json:"verificationtoken"`
}

// Login attempts to login the user.  Note that by necessity the password
// travels in the clear.
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// NewProposal attempts to submit a new proposal.
type NewProposal struct {
	Name  string     `json:"name"` // Proposal name
	Files []v1d.File `json:"files"`
}

// NewProposalReply is used to reply to the NewProposal command.
type NewProposalReply struct {
	CensorshipRecord v1d.CensorshipRecord `json:"censorshiprecord"`
}

// ProposalDetailsReply is used to reply to a proposal details command.
type ProposalDetailsReply struct {
	Proposal v1d.ProposalRecord `json:"proposal"`
}

// SetProposalStatus is used to publish or censor an unreviewed proposal.
type SetProposalStatus struct {
	Token  string      `json:"token"`
	Status v1d.StatusT `json:"status"`
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	Status v1d.StatusT `json:"status"`
}

// GetAllUnvettedReply is used to reply with a list of all unvetted proposals.
type GetAllUnvettedReply struct {
	Proposals []v1d.ProposalRecord `json:"proposals"`
}

// GetAllVettedReply is used to reply with a list of all vetted proposals.
type GetAllVettedReply struct {
	Proposals []v1d.ProposalRecord `json:"proposals"`
}

// PolicyReply is used to reply to the policy command. It returns
// the file upload restrictions set for Politeia.
type PolicyReply struct {
	MaxImages      uint     `json:"maximages"`
	MaxImageSize   uint     `json:"maximagesize"`
	MaxMDs         uint     `json:"maxmds"`
	MaxMDSize      uint     `json:"maxmdsize"`
	ValidMIMETypes []string `json:"validmimetypes"`
}
