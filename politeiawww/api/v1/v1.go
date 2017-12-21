package v1

import (
	"fmt"
)

type ErrorStatusT int
type PropStatusT int

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token"    // CSRF token for replies
	Forward   = "X-Forwarded-For" // Proxy header

	RouteUserMe              = "/user/me"
	RouteNewUser             = "/user/new"
	RouteVerifyNewUser       = "/user/verify"
	RouteUpdateUserKey       = "/user/key"
	RouteVerifyUpdateUserKey = "/user/key/verify"
	RouteChangePassword      = "/user/password/change"
	RouteResetPassword       = "/user/password/reset"
	RouteUserProposals       = "/user/proposals"
	RouteLogin               = "/login"
	RouteLogout              = "/logout"
	RouteSecret              = "/secret"
	RouteAllVetted           = "/proposals/vetted"
	RouteAllUnvetted         = "/proposals/unvetted"
	RouteNewProposal         = "/proposals/new"
	RouteProposalDetails     = "/proposals/{token:[A-z0-9]{64}}"
	RouteSetProposalStatus   = "/proposals/{token:[A-z0-9]{64}}/status"
	RoutePolicy              = "/policy"
	RouteNewComment          = "/comments/new"
	RouteCommentsGet         = "/proposals/{token:[A-z0-9]{64}}/comments"
	RouteStartVote           = "/proposals/startvote"

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

	// PolicyMaxProposalNameLength is the max length of a proposal name
	// proposal name
	PolicyMaxProposalNameLength = 80

	// PolicyMinProposalNameLength is the min length of a proposal name
	// proposal name
	PolicyMinProposalNameLength = 8

	// PolicyMaxCommentLength is the maximum number of characters
	// accepted for comments
	PolicyMaxCommentLength = 8000

	// ProposalListPageSize is the maximum number of proposals returned
	// for the routes that return lists of proposals
	ProposalListPageSize = 20

	// Error status codes
	ErrorStatusInvalid                     ErrorStatusT = 0
	ErrorStatusInvalidEmailOrPassword      ErrorStatusT = 1
	ErrorStatusMalformedEmail              ErrorStatusT = 2
	ErrorStatusVerificationTokenInvalid    ErrorStatusT = 3
	ErrorStatusVerificationTokenExpired    ErrorStatusT = 4
	ErrorStatusProposalMissingFiles        ErrorStatusT = 5
	ErrorStatusProposalNotFound            ErrorStatusT = 6
	ErrorStatusProposalDuplicateFilenames  ErrorStatusT = 7
	ErrorStatusProposalInvalidTitle        ErrorStatusT = 8
	ErrorStatusMaxMDsExceededPolicy        ErrorStatusT = 9
	ErrorStatusMaxImagesExceededPolicy     ErrorStatusT = 10
	ErrorStatusMaxMDSizeExceededPolicy     ErrorStatusT = 11
	ErrorStatusMaxImageSizeExceededPolicy  ErrorStatusT = 12
	ErrorStatusMalformedPassword           ErrorStatusT = 13
	ErrorStatusCommentNotFound             ErrorStatusT = 14
	ErrorStatusInvalidProposalName         ErrorStatusT = 15
	ErrorStatusInvalidFileDigest           ErrorStatusT = 16
	ErrorStatusInvalidBase64               ErrorStatusT = 17
	ErrorStatusInvalidMIMEType             ErrorStatusT = 18
	ErrorStatusUnsupportedMIMEType         ErrorStatusT = 19
	ErrorStatusInvalidPropStatusTransition ErrorStatusT = 20
	ErrorStatusInvalidPublicKey            ErrorStatusT = 21
	ErrorStatusNoPublicKey                 ErrorStatusT = 22
	ErrorStatusInvalidSignature            ErrorStatusT = 23
	ErrorStatusInvalidInput                ErrorStatusT = 24
	ErrorStatusInvalidSigningKey           ErrorStatusT = 25
	ErrorStatusCommentLengthExceededPolicy ErrorStatusT = 26
	ErrorStatusUserNotFound                ErrorStatusT = 27
	ErrorStatusWrongStatus                 ErrorStatusT = 28

	// Proposal status codes (set and get)
	PropStatusInvalid     PropStatusT = 0 // Invalid status
	PropStatusNotFound    PropStatusT = 1 // Proposal not found
	PropStatusNotReviewed PropStatusT = 2 // Proposal has not been reviewed
	PropStatusCensored    PropStatusT = 3 // Proposal has been censored
	PropStatusPublic      PropStatusT = 4 // Proposal is publicly visible
	PropStatusLocked      PropStatusT = 6 // Proposal is locked
)

var (
	// PolicyProposalNameSupportedCharacters is the regular expression of a valid
	// proposal name
	PolicyProposalNameSupportedCharacters = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!"}

	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/v%v", PoliteiaWWWAPIVersion)

	// CookieSession is the cookie name that indicates that a user is
	// logged in.
	CookieSession = "session"

	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:                     "invalid status",
		ErrorStatusInvalidEmailOrPassword:      "invalid email or password",
		ErrorStatusMalformedEmail:              "malformed email",
		ErrorStatusVerificationTokenInvalid:    "invalid verification token",
		ErrorStatusVerificationTokenExpired:    "expired verification token",
		ErrorStatusProposalMissingFiles:        "missing proposal files",
		ErrorStatusProposalNotFound:            "proposal not found",
		ErrorStatusProposalDuplicateFilenames:  "duplicate proposal files",
		ErrorStatusProposalInvalidTitle:        "invalid proposal title",
		ErrorStatusMaxMDsExceededPolicy:        "maximum markdown files exceeded",
		ErrorStatusMaxImagesExceededPolicy:     "maximum image files exceeded",
		ErrorStatusMaxMDSizeExceededPolicy:     "maximum markdown file size exceeded",
		ErrorStatusMaxImageSizeExceededPolicy:  "maximum image file size exceeded",
		ErrorStatusMalformedPassword:           "malformed password",
		ErrorStatusCommentNotFound:             "comment not found",
		ErrorStatusInvalidProposalName:         "invalid proposal name",
		ErrorStatusInvalidFileDigest:           "invalid file digest",
		ErrorStatusInvalidBase64:               "invalid base64 file content",
		ErrorStatusInvalidMIMEType:             "invalid MIME type detected for file",
		ErrorStatusUnsupportedMIMEType:         "unsupported MIME type for file",
		ErrorStatusInvalidPropStatusTransition: "invalid proposal status",
		ErrorStatusInvalidPublicKey:            "invalid public key",
		ErrorStatusNoPublicKey:                 "no active public key",
		ErrorStatusInvalidSignature:            "invalid signature",
		ErrorStatusInvalidInput:                "invalid input",
		ErrorStatusInvalidSigningKey:           "invalid signing key",
		ErrorStatusCommentLengthExceededPolicy: "maximum comment length exceeded",
		ErrorStatusUserNotFound:                "user not found",
		ErrorStatusWrongStatus:                 "wrong status",
	}
)

// File describes an individual file that is part of the proposal.  The
// directory structure must be flattened.  The server side SHALL verify MIME
// and Digest.
type File struct {
	// Meta-data
	Name   string `json:"name"`   // Suggested filename
	MIME   string `json:"mime"`   // Mime type
	Digest string `json:"digest"` // Digest of unencoded payload

	// Data
	Payload string `json:"payload"` // File content, base64 encoded
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
	Signature string `json:"signature"` // Server side signature of []byte(Merkle+Token)
}

// ProposalRecord is an entire proposal and it's content.
type ProposalRecord struct {
	Name        string      `json:"name"`        // Suggested short proposal name
	Status      PropStatusT `json:"status"`      // Current status of proposal
	Timestamp   int64       `json:"timestamp"`   // Last update of proposal
	UserId      string      `json:"userid"`      // ID of user who submitted proposal
	PublicKey   string      `json:"publickey"`   // Key used for signature.
	Signature   string      `json:"signature"`   // Signature of merkle root
	Files       []File      `json:"files"`       // Files that make up the proposal
	NumComments uint        `json:"numcomments"` // Number of comments on the proposal

	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// UserError represents an error that is caused by something that the user
// did (malformed input, bad timing, etc).
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PDError is emitted when an HTTP error response is returned from Politeiad
// for a request. It contains the HTTP status code and the JSON response body.
type PDError struct {
	HTTPCode   int
	ErrorReply PDErrorReply
}

// Error satisfies the error interface.
func (e PDError) Error() string {
	return fmt.Sprintf("error from politeiad: %v %v", e.HTTPCode,
		e.ErrorReply.ErrorCode)
}

// PDErrorReply is an error reply returned from Politeiad whenever an
// error occurs.
type PDErrorReply struct {
	ErrorCode    int
	ErrorContext []string
}

// ErrorReply are replies that the server returns a when it encounters an
// unrecoverable problem while executing a command.  The HTTP Error Code
// shall be 500 if it's an internal server error or 4xx if it's a user error.
type ErrorReply struct {
	ErrorCode    int64    `json:"errorcode,omitempty"`
	ErrorContext []string `json:"errorcontext,omitempty"`
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
	Email     string `json:"email"`
	Password  string `json:"password"`
	PublicKey string `json:"publickey"`
}

// NewUserReply is used to reply to the NewUser command with an error
// if the command is unsuccessful.
type NewUserReply struct {
	PaywallAddress    string  `json:"paywalladdress"`
	PaywallAmount     float64 `json:"paywallamount"`
	VerificationToken string  `json:"verificationtoken"` // Server verification token
}

// VerifyNewUser is used to perform verification for the user created through
// the NewUser command using the token provided in NewUserReply.
type VerifyNewUser struct {
	Email             string `schema:"email"`             // User email address
	VerificationToken string `schema:"verificationtoken"` // Server provided verification token
	Signature         string `schema:"signature"`         // Verification token signature
}

// VerifyNewUserReply
type VerifyNewUserReply struct{}

// UpdateUserKey is used to request a new active key.
type UpdateUserKey struct {
	PublicKey string `json:"publickey"`
}

// UpdateUserKeyReply replies to the UpdateUserKey command.
type UpdateUserKeyReply struct {
	VerificationToken string `json:"verificationtoken"` // Server verification token
}

// VerifyUpdateUserKey is used to request a new active key.
type VerifyUpdateUserKey struct {
	VerificationToken string `json:"verificationtoken"` // Server provided verification token
	Signature         string `json:"signature"`         // Verification token signature
}

// VerifyUpdateUserKeyReply replies to the VerifyUpdateUserKey command.
type VerifyUpdateUserKeyReply struct{}

// ChangePassword is used to perform a password change while the user
// is logged in.
type ChangePassword struct {
	CurrentPassword string `json:"currentpassword"`
	NewPassword     string `json:"newpassword"`
}

// ChangePasswordReply is used to perform a password change while the user
// is logged in.
type ChangePasswordReply struct{}

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
	VerificationToken string `json:"verificationtoken"`
}

// UserProposals is used to request a list of proposals that the
// user has submitted. This command optionally takes either a Before
// or After parameter, which specify a proposal's censorship token.
// If After is specified, the "page" returned starts after the proposal
// whose censorship token is provided. If Before is specified, the "page"
// returned starts before the proposal whose censorship token is provided.
type UserProposals struct {
	UserId string `schema:"userid"`
	Before string `schema:"before"`
	After  string `schema:"after"`
}

// UserProposalsReply replies to the UserProposals command with
// a list of proposals that the user has submitted.
type UserProposalsReply struct {
	Proposals []ProposalRecord `json:"proposals"`
}

// Login attempts to login the user.  Note that by necessity the password
// travels in the clear.
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginReply is used to reply to the Login command.
type LoginReply struct {
	IsAdmin        bool    `json:"isadmin"`        // Set if user is an admin
	UserID         string  `json:"userid"`         // User id
	Email          string  `json:"email"`          // User email
	PublicKey      string  `json:"publickey"`      // Active public key
	PaywallAddress string  `json:"paywalladdress"` // Registration paywall address
	PaywallAmount  float64 `json:"paywallamount"`  // Registration paywall amount in DCR
}

//Logout attempts to log the user out.
type Logout struct{}

// LogoutReply indicates whether the Logout command was success or not.
type LogoutReply struct{}

// Me asks the server to return pertinent user information.
//
// Note that MeReply is not present because LoginReply is reused
// for this endpoint.
type Me struct{}

// NewProposal attempts to submit a new proposal.
type NewProposal struct {
	Files     []File `json:"files"`     // Proposal files
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
}

// NewProposalReply is used to reply to the NewProposal command.
type NewProposalReply struct {
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalsDetails is used to retrieve a proposal.
// XXX clarify URL vs Direct
type ProposalsDetails struct {
	Token string `json:"token"`
}

// ProposalDetailsReply is used to reply to a proposal details command.
type ProposalDetailsReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// SetProposalStatus is used to publish or censor an unreviewed proposal.
type SetProposalStatus struct {
	Token          string      `json:"token"`
	ProposalStatus PropStatusT `json:"proposalstatus"`
	Signature      string      `json:"signature"` // Signature of Token+string(ProposalStatus)
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	ProposalStatus PropStatusT `json:"proposalstatus"`
}

// GetAllUnvetted retrieves all unvetted proposals; the maximum number returned
// is dictated by ProposalListPageSize. This command optionally takes either
// a Before or After parameter, which specify a proposal's censorship token.
// If After is specified, the "page" returned starts after the proposal whose
// censorship token is provided. If Before is specified, the "page" returned
// starts before the proposal whose censorship token is provided.
//
// Note: This call requires admin privileges.
type GetAllUnvetted struct {
	Before string `schema:"before"`
	After  string `schema:"after"`
}

// GetAllUnvettedReply is used to reply with a list of all unvetted proposals.
type GetAllUnvettedReply struct {
	Proposals []ProposalRecord `json:"proposals"`
}

// GetAllVetted retrieves vetted proposals; the maximum number returned is dictated
// by ProposalListPageSize. This command optionally takes either a Before or After
// parameter, which specify a proposal's censorship token. If After is specified,
// the "page" returned starts after the proposal whose censorship token is provided.
// If Before is specified, the "page" returned starts before the proposal whose
// censorship token is provided.
type GetAllVetted struct {
	Before string `schema:"before"`
	After  string `schema:"after"`
}

// GetAllVettedReply is used to reply with a list of vetted proposals.
type GetAllVettedReply struct {
	Proposals []ProposalRecord `json:"proposals"`
}

// Policy returns a struct with various maxima.  The client shall observe the
// maxima.
type Policy struct{}

// PolicyReply is used to reply to the policy command. It returns
// the file upload restrictions set for Politeia.
type PolicyReply struct {
	PasswordMinChars     uint     `json:"passwordminchars"`
	ProposalListPageSize uint     `json:"proposallistpagesize"`
	MaxImages            uint     `json:"maximages"`
	MaxImageSize         uint     `json:"maximagesize"`
	MaxMDs               uint     `json:"maxmds"`
	MaxMDSize            uint     `json:"maxmdsize"`
	ValidMIMETypes       []string `json:"validmimetypes"`
	MaxNameLength        uint     `json:"maxnamelength"`
	MinNameLength        uint     `json:"minnamelength"`
	SupportedCharacters  []string `json:"supportedcharacters"`
	MaxCommentLength     uint     `json:"maxcommentlength"`
}

// NewComment sends a comment from a user to a specific proposal.  Note that
// the user is implied by the session.
type NewComment struct {
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
}

// NewCommentReply return the site generated Comment ID or an error if
// something went wrong.
type NewCommentReply struct {
	CommentID string `json:"commentid"` // Comment ID
}

// GetComments retrieve all comments for a given proposal.
type GetComments struct{}

// Comment is the structure that describes the full server side content.  It
// includes server side meta-data as well.
type Comment struct {
	// Meta-data
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	UserID    string `json:"userid"`    // Originating user
	CommentID string `json:"commentid"` // Comment ID

	// Data
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
}

// GetCommentsReply returns the provided number of comments.
type GetCommentsReply struct {
	Comments []Comment `json:"comments"` // Comments
}

// StartVote
type StartVote struct {
	Token string `json:"token"` // Proposal that will start voting soon
	// XXX we probably need something to sign here besides the the token
	Signature string `json:"signature"` // Signature of Token
}

type StartVoteReply struct {
	Timestamp         int64 `json:"timestamp"`         // Time vote was recorded
	TimestampActivate int64 `json:"timestampactivate"` // Timestamp vote starts
	TimestampComplete int64 `json:"timestampcomplete"` // Timestamp vote ends
}
