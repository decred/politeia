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
	RouteChangeUsername      = "/user/username/change"
	RouteChangePassword      = "/user/password/change"
	RouteResetPassword       = "/user/password/reset"
	RouteUserProposals       = "/user/proposals"
	RouteVerifyUserPaymentTx = "/user/verifypaymenttx"
	RouteLogin               = "/login"
	RouteLogout              = "/logout"
	RouteSecret              = "/secret"
	RouteAllVetted           = "/proposals/vetted"
	RouteAllUnvetted         = "/proposals/unvetted"
	RouteNewProposal         = "/proposals/new"
	RouteProposalDetails     = "/proposals/{token:[A-z0-9]{64}}"
	RouteSetProposalStatus   = "/proposals/{token:[A-z0-9]{64}}/status"
	RoutePolicy              = "/policy"
	RouteVersion             = "/version"
	RouteNewComment          = "/comments/new"
	RouteLikeComment         = "/comments/like"
	RouteCommentsGet         = "/proposals/{token:[A-z0-9]{64}}/comments"
	RouteStartVote           = "/proposals/startvote"
	RouteActiveVote          = "/proposals/activevote" // XXX rename to ActiveVotes
	RouteCastVotes           = "/proposals/castvotes"
	// XXX should we use a fancy route like the one underneath?
	//RouteVoteResults    = "/proposals/{token:[A-z0-9]{64}}/votes"
	RouteVoteResults   = "/proposals/voteresults"
	RouteUsernamesById = "/usernames"

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

	// PolicyMinPasswordLength is the minimum number of characters
	// accepted for user passwords
	PolicyMinPasswordLength = 8

	// PolicyMaxUsernameLength is the max length of a username
	PolicyMaxUsernameLength = 30

	// PolicyMinUsernameLength is the min length of a username
	PolicyMinUsernameLength = 3

	// PolicyMaxProposalNameLength is the max length of a proposal name
	PolicyMaxProposalNameLength = 80

	// PolicyMinProposalNameLength is the min length of a proposal name
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
	ErrorStatusNotLoggedIn                 ErrorStatusT = 29
	ErrorStatusUserNotPaid                 ErrorStatusT = 30
	ErrorStatusReviewerAdminEqualsAuthor   ErrorStatusT = 31
	ErrorStatusMalformedUsername           ErrorStatusT = 32
	ErrorStatusDuplicateUsername           ErrorStatusT = 33
	ErrorStatusVerificationTokenUnexpired  ErrorStatusT = 34

	// Proposal status codes (set and get)
	PropStatusInvalid     PropStatusT = 0 // Invalid status
	PropStatusNotFound    PropStatusT = 1 // Proposal not found
	PropStatusNotReviewed PropStatusT = 2 // Proposal has not been reviewed
	PropStatusCensored    PropStatusT = 3 // Proposal has been censored
	PropStatusPublic      PropStatusT = 4 // Proposal is publicly visible
	PropStatusLocked      PropStatusT = 6 // Proposal is locked
)

var (
	// PolicyProposalNameSupportedChars is the regular expression of a valid
	// proposal name
	PolicyProposalNameSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!"}

	// PolicyUsernameSupportedChars is the regular expression of a valid
	// username
	PolicyUsernameSupportedChars = []string{
		"A-z", "0-9", ".", ",", ":", ";", "-", " ", "@", "+",
		"(", ")"}

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
		ErrorStatusNotLoggedIn:                 "user not logged in",
		ErrorStatusUserNotPaid:                 "user hasn't paid paywall",
		ErrorStatusReviewerAdminEqualsAuthor:   "user cannot change the status of his own proposal",
		ErrorStatusMalformedUsername:           "malformed username",
		ErrorStatusDuplicateUsername:           "duplicate username",
		ErrorStatusVerificationTokenUnexpired:  "verification token not yet expired",
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
	Username    string      `json:"username"`    // Username of user who submitted proposal
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
	TestNet bool   `json:"testnet"` // Network indicator
}

// NewUser is used to request that a new user be created within the db.
// If successful, the user will require verification before being able to login.
type NewUser struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	PublicKey string `json:"publickey"`
	Username  string `json:"username"`
}

// NewUserReply is used to reply to the NewUser command with an error
// if the command is unsuccessful.
type NewUserReply struct {
	PaywallAddress     string `json:"paywalladdress"`     // Registration paywall address
	PaywallAmount      uint64 `json:"paywallamount"`      // Registration paywall amount in atoms
	PaywallTxNotBefore int64  `json:"paywalltxnotbefore"` // Minimum timestamp for paywall tx
	VerificationToken  string `json:"verificationtoken"`  // Server verification token
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

// ChangeUsername is used to perform a username change while the user
// is logged in.
type ChangeUsername struct {
	Password    string `json:"password"`
	NewUsername string `json:"newusername"`
}

// ChangeUsernameReply is used to perform a username change while the user
// is logged in.
type ChangeUsernameReply struct{}

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

// VerifyUserPaymentTx is used to request the server to check for the
// provided transaction on the Decred blockchain and verify that it
// satisfies the requirements for a user to pay his registration fee.
type VerifyUserPaymentTx struct {
	TxId string `schema:"txid"`
}

type VerifyUserPaymentTxReply struct {
	HasPaid bool `json:"haspaid"`
}

// Login attempts to login the user.  Note that by necessity the password
// travels in the clear.
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginReply is used to reply to the Login command.
type LoginReply struct {
	IsAdmin            bool   `json:"isadmin"`            // Set if user is an admin
	UserID             string `json:"userid"`             // User id
	Email              string `json:"email"`              // User email
	Username           string `json:"username"`           // Username
	PublicKey          string `json:"publickey"`          // Active public key
	PaywallAddress     string `json:"paywalladdress"`     // Registration paywall address
	PaywallAmount      uint64 `json:"paywallamount"`      // Registration paywall amount in atoms
	PaywallTxNotBefore int64  `json:"paywalltxnotbefore"` // Minimum timestamp for paywall tx
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
	PublicKey      string      `json:"publickey"`
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	Proposal ProposalRecord `json:"proposal"`
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
	MinPasswordLength          uint     `json:"minpasswordlength"`
	MinUsernameLength          uint     `json:"minusernamelength"`
	MaxUsernameLength          uint     `json:"maxusernamelength"`
	UsernameSupportedChars     []string `json:"usernamesupportedchars"`
	ProposalListPageSize       uint     `json:"proposallistpagesize"`
	MaxImages                  uint     `json:"maximages"`
	MaxImageSize               uint     `json:"maximagesize"`
	MaxMDs                     uint     `json:"maxmds"`
	MaxMDSize                  uint     `json:"maxmdsize"`
	ValidMIMETypes             []string `json:"validmimetypes"`
	MinProposalNameLength      uint     `json:"minproposalnamelength"`
	MaxProposalNameLength      uint     `json:"maxproposalnamelength"`
	ProposalNameSupportedChars []string `json:"proposalnamesupportedchars"`
	MaxCommentLength           uint     `json:"maxcommentlength"`
	BackendPublicKey           string   `json:"backendpublickey"`
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token    string       `json:"token"`    // Token that identifies vote
	Mask     uint64       `json:"mask"`     // Valid votebits
	Duration uint32       `json:"duration"` // Duration in blocks
	Options  []VoteOption `json:"options"`  //Vote options
}

// ActiveVote obtains all proposals that have active votes.
type ActiveVote struct{}

// ProposalVoteTuple is the proposal, vote and vote details.
type ProposalVoteTuple struct {
	Proposal       ProposalRecord `json:"proposal"`       // Proposal
	StartVote      StartVote      `json:"startvote"`      // Vote bits and mask
	StartVoteReply StartVoteReply `json:"startvotereply"` // Eligible tickets and other details
}

// ActiveVoteReply returns all proposals that have active votes.
type ActiveVoteReply struct {
	Votes []ProposalVoteTuple `json:"votes"` // Active votes
}

// plugin commands
// StartVote starts the voting process for a proposal.
type StartVote struct {
	PublicKey string `json:"publickey"` // Key used for signature.
	Vote      Vote   `json:"vote"`      // Vote
	Signature string `json:"signature"` // Signature of Votehash
}

// StartVoteReply returns the eligible ticket pool.
type StartVoteReply struct {
	StartBlockHeight string   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndHeight        string   `json:"endheight"`        // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// CastVote is a signed vote.
type CastVote struct {
	Token     string `json:"token"`     // Proposal ID
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// Ballot is a batch of votes that are sent to the server.
type Ballot struct {
	Votes []CastVote `json:"votes"`
}

// CastVoteReply is the answer to the CastVote command.
type CastVoteReply struct {
	ClientSignature string `json:"clientsignature"` // Signature that was sent in
	Signature       string `json:"signature"`       // Signature of the ClientSignature
	Error           string `json:"error"`           // Error if something wen't wrong during casting a vote
}

// CastVotesReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// VoteResults retrieves a single proposal vote results from the server.
type VoteResults struct {
	Token string `json:"token"` // Censorship token
}

// VoteResultsReply returns the original proposal vote and the associated cast
// votes.
type VoteResultsReply struct {
	Vote      Vote       `json:"vote"`      // Original vote
	CastVotes []CastVote `json:"castvotes"` // Vote results
}

// Comment is the structure that describes the full server side content.  It
// includes server side meta-data as well.
type Comment struct {
	// Data generated by client
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Client Signature of Token+ParentID+Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature

	// Metadata generated by decred plugin
	CommentID   string `json:"commentid"`   // Comment ID
	Receipt     string `json:"receipt"`     // Server signature of the client Signature
	Timestamp   int64  `json:"timestamp"`   // Received UNIX timestamp
	TotalVotes  uint64 `json:"totalvotes"`  // Total number of up/down votes
	ResultVotes int64  `json:"resultvotes"` // Vote score

	// Metadata generated by www
	UserID string `json:"userid"` // User id
}

// NewComment sends a comment from a user to a specific proposal.  Note that
// the user is implied by the session.
type NewComment struct {
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Client Signature of Token+ParentID+Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature
}

// NewCommentReply returns the site generated Comment ID or an error if
// something went wrong.
type NewCommentReply struct {
	Comment Comment `json:"comment"` // Comment + receipt
}

// GetComments retrieve all comments for a given proposal.
type GetComments struct {
	Token string `json:"token"` // Censorship token
}

// GetCommentsReply returns the provided number of comments.
type GetCommentsReply struct {
	Comments []Comment `json:"comments"` // Comments
}

// LikeComment allows a user to up or down vote a comment.
type LikeComment struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Action    string `json:"Action"`    // Up or downvote (1, -1)
	Signature string `json:"signature"` // Client Signature of Token+CommentID+Action
	PublicKey string `json:"publickey"` // Pubkey used for Signature
}

// LikeCommentReply returns the current up/down vote result.
type LikeCommentReply struct {
	// XXX we probably need a sequence numkber or something here and some sort of rate limit
	Total   uint64 `json:"total"`   // Total number of up and down votes
	Result  int64  `json:"result"`  // Current tally of likes, can be negative
	Receipt string `json:"receipt"` // Server signature of client signature
}

// UsernamesById is a command to fetch all usernames by their ids.
type UsernamesById struct {
	UserIds []string `json:"userids"`
}

// UsernamesByIdReply is a reply with all the usernames that correspond
// to the given ids.
type UsernamesByIdReply struct {
	Usernames []string `json:"usernames"`
}
