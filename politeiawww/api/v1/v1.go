package v1

import (
	"fmt"
)

type StatusT int
type PropStatusT int

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token"    // CSRF token for replies
	Forward   = "X-Forwarded-For" // Proxy header

	RouteUserMe               = "/user/me"
	RouteNewUser              = "/user/new"
	RouteVerifyNewUser        = "/user/verify"
	RouteVerifyNewUserSuccess = "/user/verify/success"
	RouteVerifyNewUserFailure = "/user/verify/failure"
	RouteChangePassword       = "/user/password/change"
	RouteResetPassword        = "/user/password/reset"
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

	// PolicyPasswordMinChars is the minimum number of characters
	// accepted for user passwords
	PolicyPasswordMinChars = 8

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
	StatusMalformedPassword          StatusT = 13

	// Proposal status codes (set and get)
	PropStatusInvalid     PropStatusT = 0 // Invalid status
	PropStatusNotFound    PropStatusT = 1 // Proposal not found
	PropStatusNotReviewed PropStatusT = 2 // Proposal has not been reviewed
	PropStatusCensored    PropStatusT = 3 // Proposal has been censored
	PropStatusPublic      PropStatusT = 4 // Proposal is publicly visible
)

var (
	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/v%v", PoliteiaWWWAPIVersion)

	// CookieSession is the cookie name that indicates that a user is
	// logged in.
	CookieSession = "session"
)

// File describes an individual file that is part of the proposal.  The
// directory structure must be flattened.  The server side SHALL verify MIME
// and Digest.
type File struct {
	Name    string `json:"name"`    // Suggested filename
	MIME    string `json:"mime"`    // Mime type
	Digest  string `json:"digest"`  // Payload digest
	Payload string `json:"payload"` // File content
}

// CensorshipRecord contains the proof that a proposal was accepted for review.
// The proof is verifiable on the client side.
//
// The Merkle field contains the ordered merkle root of all files in the proposal.
// The Token field contains a random censorship token that is signed by the
// server private key.  The token can be used on the client to verify the
// authenticity of the CensorshipRecord.
type CensorshipRecord struct {
	Token     string `json:"token"`     // Censorship token
	Merkle    string `json:"merkle"`    // Merkle root of proposal
	Signature string `json:"signature"` // Signature of merkle+token
}

// ProposalRecord is an entire proposal and it's content.
type ProposalRecord struct {
	Name      string      `json:"name"`      // Suggested short proposal name
	Status    PropStatusT `json:"status"`    // Current status of proposal
	Timestamp int64       `json:"timestamp"` // Last update of proposal
	Files     []File      `json:"files"`     // Files that make up the proposal

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// InternalServerError are replies that the server returns a when it hits a
// non-client.  The HTTP Error Code shall be '500 Internal Server Error'.  By
// necesity this error is human readable.
type InternalServerError struct {
	Error string `json:"error,omitempty"`
}

// Version command is used to determine the version of the API this backend
// understands and additionally it provides the route to said API.  This call
// is required in order to establish CSRF for the session.  The client should
// verify compatibility with the server version.
type Version struct{}

// VersionReply returns information that indicates what version of the server
// is running and additionally the route to the API and the public signing key of
// the server.
type VersionReply struct {
	Version uint   `json:"version"` // politeia WWW API version
	Route   string `json:"route"`   // prefix to API calls
	PubKey  string `json:"pubkey"`  // Server public key
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
	VerificationToken string  `json:"verificationtoken"`
	ErrorCode         StatusT `json:"errorcode,omitempty"`
}

// VerifyNewUser is used to perform verification for the user created through
// the NewUser command using the token provided in NewUserReply.
type VerifyNewUser struct {
	Email             string `json:"email"`
	VerificationToken string `json:"verificationtoken"`
}

//XXX missing VerifyNewUserReply

// ChangePassword is used to perform a password change while the user
// is logged in.
type ChangePassword struct {
	CurrentPassword string `json:"currentpassword"`
	NewPassword     string `json:"newpassword"`
}

// ChangePasswordReply is used to perform a password change while the user
// is logged in.
type ChangePasswordReply struct {
	ErrorCode StatusT `json:"errorcode,omitempty"`
}

// ResetPassword is used to perform a password change when the
// user is not logged in.
type ResetPassword struct {
	Email             string `json:"email"`
	VerificationToken string `json:"verificationtoken"`
	NewPassword       string `json:"newpassword"`
}

// ResetPasswordReply is used to reply to the ResetPassword command
// with an error if the command is unsuccessful.
type ResetPasswordReply struct {
	VerificationToken string  `json:"verificationtoken"`
	ErrorCode         StatusT `json:"errorcode,omitempty"`
}

// Login attempts to login the user.  Note that by necessity the password
// travels in the clear.
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginReply is used to reply to the Login command. .  IsAdmin indicates if
// the user has publish/censor privileges.
type LoginReply struct {
	IsAdmin   bool    `json:"isadmin"`
	ErrorCode StatusT `json:"errorcode,omitempty"`
}

//Logout attempts to log the user out.
type Logout struct{}

// LogoutReply indicates whether the Logout command was success or not.
type LogoutReply struct {
	ErrorCode StatusT `json:"errorcode,omitempty"`
}

// Me asks the server to return pertinent user information.
type Me struct{}

// MeReply contains user information the UI may need to render a user specific
// page.
type MeReply struct {
	Email     string  `json:"email"`
	IsAdmin   bool    `json:"isadmin"`
	ErrorCode StatusT `json:"errorcode,omitempty"`
}

// NewProposal attempts to submit a new proposal.
type NewProposal struct {
	Name  string `json:"name"`  // Proposal name
	Files []File `json:"files"` // XXX layer violation.
}

// NewProposalReply is used to reply to the NewProposal command.
type NewProposalReply struct {
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
	ErrorCode        StatusT          `json:"errorcode,omitempty"`
}

// ProposalsDetails is used to retrieve a proposal.
// XXX clarify URL vs Direct
type ProposalsDetails struct {
	Token string `json:"token"`
}

// ProposalDetailsReply is used to reply to a proposal details command.
type ProposalDetailsReply struct {
	Proposal  ProposalRecord `json:"proposal"`
	ErrorCode StatusT        `json:"errorcode,omitempty"`
}

// SetProposalStatus is used to publish or censor an unreviewed proposal.
type SetProposalStatus struct {
	Token          string      `json:"token"`
	ProposalStatus PropStatusT `json:"proposalstatus"`
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	ProposalStatus PropStatusT `json:"proposalstatus"`
	ErrorCode      StatusT     `json:"errorcode,omitempty"`
}

// GetAllUnvetted retrieves all unvetted proposals.  This call requires admin
// privileges.
type GetAllUnvetted struct{}

// GetAllUnvettedReply is used to reply with a list of all unvetted proposals.
type GetAllUnvettedReply struct {
	Proposals []ProposalRecord `json:"proposals"`
	ErrorCode StatusT          `json:"errorcode,omitempty"`
}

// GetAllVetted retrieves all vetted proposals.
type GetAllVetted struct{}

// GetAllVettedReply is used to reply with a list of all vetted proposals.
type GetAllVettedReply struct {
	Proposals []ProposalRecord `json:"proposals"`
	ErrorCode StatusT          `json:"errorcode,omitempty"`
}

// Policy returns a struct with various maxima.  The client shall observe the
// maxima.
type Policy struct{}

// PolicyReply is used to reply to the policy command. It returns
// the file upload restrictions set for Politeia.
type PolicyReply struct {
	PasswordMinChars uint     `json:"passwordminchars"`
	MaxImages        uint     `json:"maximages"`
	MaxImageSize     uint     `json:"maximagesize"`
	MaxMDs           uint     `json:"maxmds"`
	MaxMDSize        uint     `json:"maxmdsize"`
	ValidMIMETypes   []string `json:"validmimetypes"`
	ErrorCode        StatusT  `json:"errorcode,omitempty"`
}
