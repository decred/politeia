package v1

import (
	"fmt"

	v1d "github.com/decred/politeia/politeiad/api/v1"
)

type StatusT int

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteNewUser              = "/user/new"
	RouteVerifyNewUser        = "/user/verify"
	RouteVerifyNewUserSuccess = "/user/verify/success"
	RouteVerifyNewUserFailure = "/user/verify/failure"
	RouteLogin                = "/login"
	RouteLogout               = "/logout"
	RouteSecret               = "/secret"
	RouteAllVetted            = "/proposals/vetted"
	RouteAllUnvetted          = "/proposals/unvetted"
	RouteNewProposal          = "/proposals/new"
	RouteProposalDetails      = "/proposals/{token:[A-z0-9]{64}}"
	RouteSetProposalStatus    = "/proposals/{token:[A-z0-9]{64}}/setstatus"
	RoutePolicy               = "/policy"

	// VerificationTokenSize is the size of verification token in bytes
	VerificationTokenSize = 32

	// VerificationExpiryHours is the number of hours before the
	// verification token expires
	VerificationExpiryHours = 48

	// PolicyMaxImages is the maximum number of images accepted
	// when creating a new proposal
	PolicyMaxImages = 5

	// PolicyMaxImageSize is the maximum image file size (in bytes)
	// accepted when creating a new proposal
	PolicyMaxImageSize = 512 * 1024

	// PolicyMaxMDs is the maximum number of markdown files accepted
	// when creating a new proposal
	PolicyMaxMDs = 1

	// PolicyMaxMDSize is the maximum markdown file size (in bytes)
	// accepted when creating a new proposal
	PolicyMaxMDSize = 512 * 1024

	// Error status codes
	StatusInvalid                    StatusT = 0
	StatusSuccess                    StatusT = 1
	StatusInvalidEmailOrPassword     StatusT = 2
	StatusMalformedEmail             StatusT = 3
	StatusVerificationTokenInvalid   StatusT = 4
	StatusVerificationTokenExpired   StatusT = 5
	StatusProposalMissingName        StatusT = 6
	StatusProposalMissingDescription StatusT = 7
	StatusProposalNotFound           StatusT = 8
	StatusMaxMDsExceededPolicy       StatusT = 9
	StatusMaxImagesExceededPolicy    StatusT = 10
	StatusMaxMDSizeExceededPolicy    StatusT = 11
	StatusMaxImageSizeExceededPolicy StatusT = 12
)

var (
	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/v%v", PoliteiaWWWAPIVersion)

	// CookieSession is the cookie name that indicates that a user is
	// logged in.
	CookieSession = "session"
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

// NewUserReply is used to reply to the NewUser command with an error
// if the command is unsuccessful.
type NewUserReply struct {
	ErrorCode StatusT `json:"errorcode,omitempty"`
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

// User holds basic information for the user upon login.
type User struct {
	ID    uint64 `json:"id"`
	Email string `json:"email"`
	Admin bool   `json:"admin,omitempty"`
}

// LoginReply is used to reply to the Login command. It holds
// either basic information about the just-logged-in user or
// a login error.
type LoginReply struct {
	User      User    `json:"user"`
	ErrorCode StatusT `json:"errorcode,omitempty"`
}

// NewProposal attempts to submit a new proposal.
type NewProposal struct {
	Name  string     `json:"name"` // Proposal name
	Files []v1d.File `json:"files"`
}

// NewProposalReply is used to reply to the NewProposal command.
type NewProposalReply struct {
	CensorshipRecord v1d.CensorshipRecord `json:"censorshiprecord"`
	ErrorCode        StatusT              `json:"errorcode,omitempty"`
}

// ProposalDetailsReply is used to reply to a proposal details command.
type ProposalDetailsReply struct {
	Proposal  v1d.ProposalRecord `json:"proposal"`
	ErrorCode StatusT            `json:"errorcode,omitempty"`
}

// SetProposalStatus is used to publish or censor an unreviewed proposal.
type SetProposalStatus struct {
	Token  string      `json:"token"`
	Status v1d.StatusT `json:"status"`
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	Status    v1d.StatusT `json:"status"`
	ErrorCode StatusT     `json:"errorcode,omitempty"`
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
