// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"

	"github.com/decred/politeia/decredplugin"
)

type ErrorStatusT int
type PropStateT int
type PropStatusT int
type PropVoteStatusT int
type UserManageActionT int
type EmailNotificationT int
type VoteT int
type TOTPMethodT int

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token"    // CSRF token for replies
	Forward   = "X-Forwarded-For" // Proxy header

	RouteVersion                  = "/version"
	RoutePolicy                   = "/policy"
	RouteSecret                   = "/secret"
	RouteLogin                    = "/login"
	RouteLogout                   = "/logout"
	RouteUserMe                   = "/user/me"
	RouteNewUser                  = "/user/new"
	RouteResendVerification       = "/user/new/resend"
	RouteVerifyNewUser            = "/user/verify"
	RouteEditUser                 = "/user/edit"
	RouteUpdateUserKey            = "/user/key"
	RouteVerifyUpdateUserKey      = "/user/key/verify"
	RouteChangeUsername           = "/user/username/change"
	RouteChangePassword           = "/user/password/change"
	RouteResetPassword            = "/user/password/reset"
	RouteVerifyResetPassword      = "/user/password/reset/verify"
	RouteUserRegistrationPayment  = "/user/payments/registration"
	RouteUserProposalPaywall      = "/user/payments/paywall"
	RouteUserProposalPaywallTx    = "/user/payments/paywalltx"
	RouteUserProposalCredits      = "/user/payments/credits"
	RouteUserPaymentsRescan       = "/user/payments/rescan"
	RouteManageUser               = "/user/manage"
	RouteSetTOTP                  = "/user/totp"
	RouteVerifyTOTP               = "/user/verifytotp"
	RouteUserDetails              = "/user/{userid:[0-9a-zA-Z-]{36}}"
	RouteUsers                    = "/users"
	RouteUnauthenticatedWebSocket = "/ws"
	RouteAuthenticatedWebSocket   = "/aws"

	// The following routes WILL BE DEPRECATED in the near future and
	// should not be used. The pi v1 API should be used instead.
	RouteTokenInventory   = "/proposals/tokeninventory"
	RouteProposalDetails  = "/proposals/{token:[A-Fa-f0-9]{7,64}}"
	RouteBatchProposals   = "/proposals/batch"
	RouteVoteResults      = "/proposals/{token:[A-Fa-f0-9]{7,64}}/votes"
	RouteCastVotes        = "/proposals/castvotes"
	RouteBatchVoteSummary = "/proposals/batchvotesummary"

	// The following route HAVE BEEN DEPRECATED. The pi v1 API should
	// be used instead.
	RouteActiveVote        = "/proposals/activevote"
	RouteAllVetted         = "/proposals/vetted"
	RouteNewProposal       = "/proposals/new"
	RouteEditProposal      = "/proposals/edit"
	RouteAuthorizeVote     = "/proposals/authorizevote"
	RouteStartVote         = "/proposals/startvote"
	RouteAllVoteStatus     = "/proposals/votestatus"
	RouteSetProposalStatus = "/proposals/{token:[A-Fa-f0-9]{7,64}}/status"
	RouteCommentsGet       = "/proposals/{token:[A-Fa-f0-9]{7,64}}/comments"
	RouteVoteStatus        = "/proposals/{token:[A-Fa-f0-9]{7,64}}/votestatus"
	RouteNewComment        = "/comments/new"
	RouteLikeComment       = "/comments/like"
	RouteCensorComment     = "/comments/censor"
	RouteUserCommentsLikes = "/user/proposals/{token:[A-z0-9]{64}}/commentslikes"
	RouteUserProposals     = "/user/proposals"

	// VerificationTokenSize is the size of verification token in bytes
	VerificationTokenSize = 32

	// TokenPrefixLength is the length of the token prefix that can
	// be used in RouteProposalDetails. This should match what is defined
	// in politeiad, and once a Policy route is created in politeiad,
	// this should be removed.
	TokenPrefixLength = 7

	// VerificationExpiryHours is the number of hours before the
	// verification token expires
	VerificationExpiryHours = 24

	// PolicyIdexFilename is the file name of the proposal markdown
	// file. Every proposal is required to have a index file. The index
	// file should contain the proposal content.
	PolicyIndexFilename = "index.md"

	// PolicyMaxImages is the maximum number of images accepted
	// when creating a new proposal
	PolicyMaxImages = 5

	// PolicyMaxImageSize is the maximum image file size (in bytes)
	// accepted when creating a new proposal
	PolicyMaxImageSize = 512 * 1024

	// PolicyMaxMDs is the maximum number of markdown files accepted
	// when creating a new proposal.
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

	// UserListPageSize is the maximum number of users returned
	// for the routes that return lists of users
	UserListPageSize = 20

	// Error status codes
	ErrorStatusInvalid                     ErrorStatusT = 0
	ErrorStatusInvalidPassword             ErrorStatusT = 1
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
	ErrorStatusInvalidFilename             ErrorStatusT = 15
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
	ErrorStatusCannotVerifyPayment         ErrorStatusT = 35
	ErrorStatusDuplicatePublicKey          ErrorStatusT = 36
	ErrorStatusInvalidPropVoteStatus       ErrorStatusT = 37
	ErrorStatusUserLocked                  ErrorStatusT = 38
	ErrorStatusNoProposalCredits           ErrorStatusT = 39
	ErrorStatusInvalidUserManageAction     ErrorStatusT = 40
	ErrorStatusUserActionNotAllowed        ErrorStatusT = 41
	ErrorStatusWrongVoteStatus             ErrorStatusT = 42
	ErrorStatusCannotVoteOnPropComment     ErrorStatusT = 44
	ErrorStatusChangeMessageCannotBeBlank  ErrorStatusT = 45
	ErrorStatusCensorReasonCannotBeBlank   ErrorStatusT = 46
	ErrorStatusCannotCensorComment         ErrorStatusT = 47
	ErrorStatusUserNotAuthor               ErrorStatusT = 48
	ErrorStatusVoteNotAuthorized           ErrorStatusT = 49
	ErrorStatusVoteAlreadyAuthorized       ErrorStatusT = 50
	ErrorStatusInvalidAuthVoteAction       ErrorStatusT = 51
	ErrorStatusUserDeactivated             ErrorStatusT = 52
	ErrorStatusInvalidPropVoteBits         ErrorStatusT = 53
	ErrorStatusInvalidPropVoteParams       ErrorStatusT = 54
	ErrorStatusEmailNotVerified            ErrorStatusT = 55
	ErrorStatusInvalidUUID                 ErrorStatusT = 56
	ErrorStatusInvalidLikeCommentAction    ErrorStatusT = 57
	ErrorStatusInvalidCensorshipToken      ErrorStatusT = 58
	ErrorStatusEmailAlreadyVerified        ErrorStatusT = 59
	ErrorStatusNoProposalChanges           ErrorStatusT = 60
	ErrorStatusMaxProposalsExceededPolicy  ErrorStatusT = 61
	ErrorStatusDuplicateComment            ErrorStatusT = 62
	ErrorStatusInvalidLogin                ErrorStatusT = 63
	ErrorStatusCommentIsCensored           ErrorStatusT = 64
	ErrorStatusInvalidProposalVersion      ErrorStatusT = 65
	ErrorStatusMetadataInvalid             ErrorStatusT = 66
	ErrorStatusMetadataMissing             ErrorStatusT = 67
	ErrorStatusMetadataDigestInvalid       ErrorStatusT = 68
	ErrorStatusInvalidVoteType             ErrorStatusT = 69
	ErrorStatusInvalidVoteOptions          ErrorStatusT = 70
	ErrorStatusLinkByDeadlineNotMet        ErrorStatusT = 71
	ErrorStatusNoLinkedProposals           ErrorStatusT = 72
	ErrorStatusInvalidLinkTo               ErrorStatusT = 73
	ErrorStatusInvalidLinkBy               ErrorStatusT = 74
	ErrorStatusInvalidRunoffVote           ErrorStatusT = 75
	ErrorStatusWrongProposalType           ErrorStatusT = 76
	ErrorStatusTOTPFailedValidation        ErrorStatusT = 77
	ErrorStatusTOTPInvalidType             ErrorStatusT = 78

	// Proposal state codes
	//
	// PropStateUnvetted includes proposals with a status of:
	//   * PropStatusNotReviewed
	//   * PropStatusUnreviewedChanges
	//   * PropStatusCensored
	// PropStateVetted includes proposals with a status of:
	//   * PropStatusPublic
	//   * PropStatusAbandoned
	//
	// Proposal states correspond to the unvetted and vetted politeiad
	// repositories.
	PropStateInvalid  PropStateT = 0 // Invalid state
	PropStateUnvetted PropStateT = 1 // Unvetted proposal
	PropStateVetted   PropStateT = 2 // Vetted proposal

	// Proposal status codes (set and get)
	PropStatusInvalid           PropStatusT = 0 // Invalid status
	PropStatusNotFound          PropStatusT = 1 // Proposal not found
	PropStatusNotReviewed       PropStatusT = 2 // Proposal has not been reviewed
	PropStatusCensored          PropStatusT = 3 // Proposal has been censored
	PropStatusPublic            PropStatusT = 4 // Proposal is publicly visible
	PropStatusUnreviewedChanges PropStatusT = 5 // Proposal is not public and has unreviewed changes
	PropStatusAbandoned         PropStatusT = 6 // Proposal has been declared abandoned by an admin

	// Proposal vote status codes
	PropVoteStatusInvalid       PropVoteStatusT = 0 // Invalid vote status
	PropVoteStatusNotAuthorized PropVoteStatusT = 1 // Vote has not been authorized by author
	PropVoteStatusAuthorized    PropVoteStatusT = 2 // Vote has been authorized by author
	PropVoteStatusStarted       PropVoteStatusT = 3 // Proposal vote has been started
	PropVoteStatusFinished      PropVoteStatusT = 4 // Proposal vote has been finished
	PropVoteStatusDoesntExist   PropVoteStatusT = 5 // Proposal doesn't exist

	// Vote types
	//
	// VoteTypeStandard is used to indicate a simple approve or reject
	// proposal vote where the winner is the voting option that has met
	// the specified pass and quorum requirements.
	//
	// VoteTypeRunoff specifies a runoff vote that multiple proposals compete in.
	// All proposals are voted on like normal, but there can only be one winner
	// in a runoff vote. The winner is the proposal that meets the quorum
	// requirement, meets the pass requirement, and that has the most net yes
	// votes. The winning proposal is considered approved and all other proposals
	// are considered rejected. If no proposals meet the quorum and pass
	// requirements then all proposals are considered rejected.
	// Note: in a runoff vote it is possible for a proposal to meet the quorum
	// and pass requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeInvalid  VoteT = 0
	VoteTypeStandard VoteT = 1
	VoteTypeRunoff   VoteT = 2

	// User manage actions
	UserManageInvalid                         UserManageActionT = 0 // Invalid action type
	UserManageExpireNewUserVerification       UserManageActionT = 1
	UserManageExpireUpdateKeyVerification     UserManageActionT = 2
	UserManageExpireResetPasswordVerification UserManageActionT = 3
	UserManageClearUserPaywall                UserManageActionT = 4
	UserManageUnlock                          UserManageActionT = 5
	UserManageDeactivate                      UserManageActionT = 6
	UserManageReactivate                      UserManageActionT = 7

	// Email notification types
	NotificationEmailMyProposalStatusChange      EmailNotificationT = 1 << 0
	NotificationEmailMyProposalVoteStarted       EmailNotificationT = 1 << 1
	NotificationEmailRegularProposalVetted       EmailNotificationT = 1 << 2
	NotificationEmailRegularProposalEdited       EmailNotificationT = 1 << 3
	NotificationEmailRegularProposalVoteStarted  EmailNotificationT = 1 << 4
	NotificationEmailAdminProposalNew            EmailNotificationT = 1 << 5
	NotificationEmailAdminProposalVoteAuthorized EmailNotificationT = 1 << 6
	NotificationEmailCommentOnMyProposal         EmailNotificationT = 1 << 7
	NotificationEmailCommentOnMyComment          EmailNotificationT = 1 << 8

	// Time-base one time password types
	TOTPTypeInvalid TOTPMethodT = 0 // Invalid TOTP type
	TOTPTypeBasic   TOTPMethodT = 1
)

var (
	// PolicyProposalNameSupportedChars is the regular expression of a valid
	// proposal name
	PolicyProposalNameSupportedChars = []string{
		"A-z", "0-9", "&", ".", ",", ":", ";", "-", " ", "@", "+", "#", "/",
		"(", ")", "!", "?", "\"", "'"}

	// PolicyUsernameSupportedChars is the regular expression of a valid
	// username
	PolicyUsernameSupportedChars = []string{
		"a-z", "0-9", ".", ",", ":", ";", "-", "@", "+", "(", ")", "_"}

	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/v%v", PoliteiaWWWAPIVersion)

	// CookieSession is the cookie name that indicates that a user is
	// logged in.
	CookieSession = "session"

	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:                     "invalid error status",
		ErrorStatusInvalidPassword:             "invalid password",
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
		ErrorStatusInvalidFilename:             "invalid filename",
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
		ErrorStatusWrongStatus:                 "wrong proposal status",
		ErrorStatusNotLoggedIn:                 "user not logged in",
		ErrorStatusUserNotPaid:                 "user hasn't paid paywall",
		ErrorStatusReviewerAdminEqualsAuthor:   "user cannot change the status of his own proposal",
		ErrorStatusMalformedUsername:           "malformed username",
		ErrorStatusDuplicateUsername:           "duplicate username",
		ErrorStatusVerificationTokenUnexpired:  "verification token not yet expired",
		ErrorStatusCannotVerifyPayment:         "cannot verify payment at this time",
		ErrorStatusDuplicatePublicKey:          "public key already taken by another user",
		ErrorStatusInvalidPropVoteStatus:       "invalid proposal vote status",
		ErrorStatusUserLocked:                  "user locked due to too many login attempts",
		ErrorStatusNoProposalCredits:           "no proposal credits",
		ErrorStatusInvalidUserManageAction:     "invalid user edit action",
		ErrorStatusUserActionNotAllowed:        "user action is not allowed",
		ErrorStatusWrongVoteStatus:             "wrong proposal vote status",
		ErrorStatusCannotVoteOnPropComment:     "cannot vote on proposal comment",
		ErrorStatusChangeMessageCannotBeBlank:  "status change message cannot be blank",
		ErrorStatusCensorReasonCannotBeBlank:   "censor comment reason cannot be blank",
		ErrorStatusCannotCensorComment:         "cannot censor comment",
		ErrorStatusUserNotAuthor:               "user is not the proposal author",
		ErrorStatusVoteNotAuthorized:           "vote has not been authorized",
		ErrorStatusVoteAlreadyAuthorized:       "vote has already been authorized",
		ErrorStatusInvalidAuthVoteAction:       "invalid authorize vote action",
		ErrorStatusUserDeactivated:             "user account is deactivated",
		ErrorStatusInvalidPropVoteBits:         "invalid proposal vote option bits",
		ErrorStatusInvalidPropVoteParams:       "invalid proposal vote parameters",
		ErrorStatusEmailNotVerified:            "email address is not verified",
		ErrorStatusInvalidUUID:                 "invalid user UUID",
		ErrorStatusInvalidLikeCommentAction:    "invalid like comment action",
		ErrorStatusInvalidCensorshipToken:      "invalid proposal censorship token",
		ErrorStatusEmailAlreadyVerified:        "email address is already verified",
		ErrorStatusNoProposalChanges:           "no changes found in proposal",
		ErrorStatusDuplicateComment:            "duplicate comment",
		ErrorStatusInvalidLogin:                "invalid login credentials",
		ErrorStatusCommentIsCensored:           "comment is censored",
		ErrorStatusInvalidProposalVersion:      "invalid proposal version",
		ErrorStatusMetadataInvalid:             "invalid metadata",
		ErrorStatusMetadataMissing:             "missing metadata",
		ErrorStatusMetadataDigestInvalid:       "metadata digest invalid",
		ErrorStatusInvalidVoteType:             "invalid vote type",
		ErrorStatusInvalidVoteOptions:          "invalid vote options",
		ErrorStatusLinkByDeadlineNotMet:        "linkby deadline note met yet",
		ErrorStatusNoLinkedProposals:           "no linked proposals",
		ErrorStatusInvalidLinkTo:               "invalid proposal linkto",
		ErrorStatusInvalidLinkBy:               "invalid proposal linkby",
		ErrorStatusInvalidRunoffVote:           "invalid runoff vote",
		ErrorStatusWrongProposalType:           "wrong proposal type",
		ErrorStatusTOTPFailedValidation:        "the provided passcode does not match the saved secret key",
		ErrorStatusTOTPInvalidType:             "invalid totp type",
	}

	// PropStatus converts propsal status codes to human readable text
	PropStatus = map[PropStatusT]string{
		PropStatusInvalid:     "invalid proposal status",
		PropStatusNotFound:    "not found",
		PropStatusNotReviewed: "unreviewed",
		PropStatusCensored:    "censored",
		PropStatusPublic:      "public",
		PropStatusAbandoned:   "abandoned",
	}

	// PropVoteStatus converts votes status codes to human readable text
	PropVoteStatus = map[PropVoteStatusT]string{
		PropVoteStatusInvalid:       "invalid vote status",
		PropVoteStatusNotAuthorized: "voting has not been authorized by author",
		PropVoteStatusAuthorized:    "voting has been authorized by author",
		PropVoteStatusStarted:       "voting active",
		PropVoteStatusFinished:      "voting finished",
		PropVoteStatusDoesntExist:   "proposal does not exist",
	}

	// UserManageAction converts user edit actions to human readable text
	UserManageAction = map[UserManageActionT]string{
		UserManageInvalid:                         "invalid action",
		UserManageExpireNewUserVerification:       "expire new user verification",
		UserManageExpireUpdateKeyVerification:     "expire update key verification",
		UserManageExpireResetPasswordVerification: "expire reset password verification",
		UserManageClearUserPaywall:                "clear user paywall",
		UserManageUnlock:                          "unlock user",
		UserManageDeactivate:                      "deactivate user",
		UserManageReactivate:                      "reactivate user",
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

const (
	// Metadata hints
	HintProposalMetadata = "proposalmetadata"
)

// ProposalMetadata contains metadata that is specified by the user on proposal
// submission. It is attached to a proposal submission as a Metadata object.
//
// LinkBy must allow for a minimum of one week after the proposal vote ends for
// RFP submissions to be submitted. The LinkBy field is validated on both
// proposal submission and before the proposal vote is started to ensure that
// the RFP submissions have sufficient time to be submitted.
type ProposalMetadata struct {
	Name   string `json:"name"`             // Proposal name
	LinkTo string `json:"linkto,omitempty"` // Token of proposal to link to
	LinkBy int64  `json:"linkby,omitempty"` // UNIX timestamp of RFP deadline
}

// Metadata describes user specified metadata.
//
// Payload is the base64 encoding of the JSON encoded metadata. Its required
// to be base64 encoded because it's stored in politeiad as a file and the
// politeiad file payload must be base64.
type Metadata struct {
	Digest  string `json:"digest"`  // SHA256 digest of JSON encoded payload
	Hint    string `json:"hint"`    // Hint that describes the payload
	Payload string `json:"payload"` // Base64 encoded metadata content
}

// CensorshipRecord contains the proof that a proposal was accepted for review.
// The proof is verifiable on the client side.
//
// The Merkle field contains the ordered merkle root of all files and metadata
// in the proposal.  The Token field contains a random censorship token that is
// signed by the server private key.  The token can be used on the client to
// verify the authenticity of the CensorshipRecord.
type CensorshipRecord struct {
	Token     string `json:"token"`     // Censorship token
	Merkle    string `json:"merkle"`    // Merkle root of proposal
	Signature string `json:"signature"` // Server side signature of []byte(Merkle+Token)
}

// VoteSummary contains a summary of the vote information for a specific
// proposal. It is a light weight version of the VoteResultsReply that is used
// when the full ticket snapshot or the full cast vote data is not needed.
type VoteSummary struct {
	Status           PropVoteStatusT    `json:"status"`                     // Vote status
	Approved         bool               `json:"approved"`                   // Was the vote approved
	Type             VoteT              `json:"type,omitempty"`             // Vote type
	EligibleTickets  uint32             `json:"eligibletickets,omitempty"`  // Number of eligible tickets
	Duration         uint32             `json:"duration,omitempty"`         // Duration of vote
	EndHeight        uint64             `json:"endheight,omitempty"`        // Vote end height
	QuorumPercentage uint32             `json:"quorumpercentage,omitempty"` // Percent of eligible votes required for quorum
	PassPercentage   uint32             `json:"passpercentage,omitempty"`   // Percent of total votes required to pass
	Results          []VoteOptionResult `json:"results,omitempty"`          // Vote results
}

// ProposalRecord is an entire proposal and it's content.
//
// Signature is a signature of the proposal merkle root where the merkle root
// contains all Files and Metadata of the proposal.
type ProposalRecord struct {
	Name                string      `json:"name"`                          // Suggested short proposal name
	State               PropStateT  `json:"state"`                         // Current state of proposal
	Status              PropStatusT `json:"status"`                        // Current status of proposal
	Timestamp           int64       `json:"timestamp"`                     // Last update of proposal
	UserId              string      `json:"userid"`                        // ID of user who submitted proposal
	Username            string      `json:"username"`                      // Username of user who submitted proposal
	PublicKey           string      `json:"publickey"`                     // Key used for signature.
	Signature           string      `json:"signature"`                     // Signature of merkle root
	NumComments         uint        `json:"numcomments"`                   // Number of comments on the proposal
	Version             string      `json:"version"`                       // Record version
	StatusChangeMessage string      `json:"statuschangemessage,omitempty"` // Message associated to the status change
	PublishedAt         int64       `json:"publishedat,omitempty"`         // UNIX timestamp of when proposal was published
	CensoredAt          int64       `json:"censoredat,omitempty"`          // UNIX timestamp of when proposal was censored
	AbandonedAt         int64       `json:"abandonedat,omitempty"`         // UNIX timestamp of when proposal was abandoned
	LinkTo              string      `json:"linkto,omitempty"`              // Token of linked parent proposal
	LinkBy              int64       `json:"linkby,omitempty"`              // UNIX timestamp of RFP deadline
	LinkedFrom          []string    `json:"linkedfrom,omitempty"`          // Tokens of public props that have linked to this this prop

	Files            []File           `json:"files"`
	Metadata         []Metadata       `json:"metadata"`
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalCredit contains the details of a proposal credit that has been
// purchased by the user.
type ProposalCredit struct {
	PaywallID     uint64 `json:"paywallid"`     // paywall that created this credit
	Price         uint64 `json:"price"`         // Price credit was purchased at in atoms
	DatePurchased int64  `json:"datepurchased"` // Unix timestamp of the purchase date
	TxID          string `json:"txid"`          // Decred tx that purchased this credit
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

// ErrorReply are replies that the server returns when it encounters an
// unrecoverable problem while executing a command. The HTTP status code will
// be 500 and the ErrorCode field will contain a UNIX timestamp that the user
// can provide to the server admin to track down the error details in the logs.
type ErrorReply struct {
	ErrorCode    int64    `json:"errorcode,omitempty"`
	ErrorContext []string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e ErrorReply) Error() string {
	return fmt.Sprintf("server error: %v", e.ErrorCode)
}

// Version command is used to determine the lowest API version that this
// backend supports and additionally it provides the route to said API.  This
// call is required in order to establish CSRF for the session.  The client
// should verify compatibility with the server version.
type Version struct{}

// VersionReply returns information that indicates the lowest version that
// this backend supports and additionally the route to the API and the public
// signing key of the server.
type VersionReply struct {
	Version           uint   `json:"version"`           // Lowest supported WWW API version
	Route             string `json:"route"`             // Prefix to API calls
	BuildVersion      string `json:"buildversion"`      // Build version from hosted pi module
	PubKey            string `json:"pubkey"`            // Server public key
	TestNet           bool   `json:"testnet"`           // Network indicator
	Mode              string `json:"mode"`              // current politeiawww mode running (piwww or cmswww)
	ActiveUserSession bool   `json:"activeusersession"` // indicates if there is an active user session
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
	VerificationToken string `json:"verificationtoken"` // Server verification token
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

// ResendVerification is used to resent a new user verification email.
type ResendVerification struct {
	Email     string `json:"email"`
	PublicKey string `json:"publickey"`
}

// ResendVerificationReply is used to reply to the ResendVerification command.
type ResendVerificationReply struct {
	VerificationToken string `json:"verificationtoken"` // Server verification token
}

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

// ResetPassword is used to perform a password change when the user is not
// logged in. If the username and email address match the user record in the
// database then a reset password verification token will be email to the user.
type ResetPassword struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// ResetPasswordReply is used to reply to the ResetPassword command. The
// verification token will only be present if the email server has been
// disabled.
type ResetPasswordReply struct {
	VerificationToken string `json:"verificationtoken"`
}

// VerifyResetPassword is used to verify the verification token sent to a user
// in the ResestPassword command and will update the user's password with the
// provided NewPassword if everything matches.
type VerifyResetPassword struct {
	Username          string `json:"username"`
	VerificationToken string `json:"verificationtoken"`
	NewPassword       string `json:"newpassword"`
}

// VerifyResetPasswordReply is used to reply to the VerifyResetPassword
// command.
type VerifyResetPasswordReply struct{}

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
// a list of proposals that the user has submitted and the total
// amount of proposals
type UserProposalsReply struct {
	Proposals      []ProposalRecord `json:"proposals"`      // user proposals
	NumOfProposals int              `json:"numofproposals"` // number of proposals submitted by the user
}

// Users is used to request a list of users given a filter.
type Users struct {
	Username  string `json:"username"`  // String which should match or partially match a username
	Email     string `json:"email"`     // String which should match or partially match an email
	PublicKey string `json:"publickey"` // Active or inactive user pubkey

}

// UsersReply is a reply to the Users command, replying with a list of users.
type UsersReply struct {
	TotalUsers   uint64         `json:"totalusers,omitempty"` // Total number of all users in the database
	TotalMatches uint64         `json:"totalmatches"`         // Total number of users that match the filters
	Users        []AbridgedUser `json:"users"`                // List of users that match the filters
}

// AbridgedUser is a shortened version of User that's used for the admin list.
type AbridgedUser struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username"`
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
	PaywallTxID        string `json:"paywalltxid"`        // Paywall payment tx ID
	ProposalCredits    uint64 `json:"proposalcredits"`    // Number of the proposal credits the user has available to spend
	LastLoginTime      int64  `json:"lastlogintime"`      // Unix timestamp of last login date
	SessionMaxAge      int64  `json:"sessionmaxage"`      // Unix timestamp of session max age
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

// UserRegistrationPayment is used to request the server to check for the
// provided transaction on the Decred blockchain and verify that it
// satisfies the requirements for a user to pay his registration fee.
type UserRegistrationPayment struct{}

// UserRegistrationPaymentReply is used to reply to the UserRegistrationPayment
// command.
type UserRegistrationPaymentReply struct {
	HasPaid            bool   `json:"haspaid"`
	PaywallAddress     string `json:"paywalladdress"`     // Registration paywall address
	PaywallAmount      uint64 `json:"paywallamount"`      // Registration paywall amount in atoms
	PaywallTxNotBefore int64  `json:"paywalltxnotbefore"` // Minimum timestamp for paywall tx
}

// UserProposalPaywall is used to request proposal paywall details from the
// server that the user needs in order to purchase paywall credits.
type UserProposalPaywall struct{}

// UserProposalPaywallReply is used to reply to the UserProposalPaywall
// command.
type UserProposalPaywallReply struct {
	CreditPrice        uint64 `json:"creditprice"`        // Cost per proposal credit in atoms
	PaywallAddress     string `json:"paywalladdress"`     // Proposal paywall address
	PaywallTxNotBefore int64  `json:"paywalltxnotbefore"` // Minimum timestamp for paywall tx
}

// UserProposalPaywallTx is used to request payment details for a pending
// proposal paywall payment.
type UserProposalPaywallTx struct{}

// UserProposalPaywallTxReply is used to reply to the ProposalPaywallPayment
// command.
type UserProposalPaywallTxReply struct {
	TxID          string `json:"txid"`          // Transaction ID
	TxAmount      uint64 `json:"amount"`        // Transaction amount in atoms
	Confirmations uint64 `json:"confirmations"` // Number of block confirmations
}

// UserProposalCredits is used to request a list of all the user's unspent
// proposal credits and a list of all of the user's spent proposal credits.
// A spent credit means that the credit was used to submit a proposal.  Spent
// credits have a proposal censorship token associated with them to signify
// that they have been spent.
type UserProposalCredits struct{}

// UserProposalCreditsReply is used to reply to the UserProposalCredits command.
// It contains unspent credits that the user purchased but did not yet use, and
// the credits the user already spent to submit proposals.
type UserProposalCreditsReply struct {
	UnspentCredits []ProposalCredit `json:"unspentcredits"`
	SpentCredits   []ProposalCredit `json:"spentcredits"`
}

// UserPaymentsRescan allows an admin to rescan a user's paywall address to
// check for any payments that may have been missed by paywall polling. Any
// proposal credits that are created as a result of the rescan are returned in
// the UserPaymentsRescanReply. This call isn't RESTful, but a PUT request is
// used since it's idempotent.
type UserPaymentsRescan struct {
	UserID string `json:"userid"` // ID of user to rescan
}

// UserPaymentsRescanReply is used to reply to the UserPaymentsRescan command.
// Returns the credits that were created by the rescan.
type UserPaymentsRescanReply struct {
	NewCredits []ProposalCredit `json:"newcredits"`
}

// NewProposal attempts to submit a new proposal.
//
// Metadata is required to include a ProposalMetadata for all proposal
// submissions.
//
// Signature is the signature of the proposal merkle root. The merkle root
// contains the ordered files and metadata digests. The file digests are first
// in the ordering.
type NewProposal struct {
	Files     []File     `json:"files"`     // Proposal files
	Metadata  []Metadata `json:"metadata"`  // User specified metadata
	PublicKey string     `json:"publickey"` // Key used for signature.
	Signature string     `json:"signature"` // Signature of merkle root
}

// NewProposalReply is used to reply to the NewProposal command
type NewProposalReply struct {
	CensorshipRecord CensorshipRecord `json:"censorshiprecord"`
}

// ProposalsDetails is used to retrieve a proposal by it's token
// and by the proposal version (optional). If the version isn't specified
// the latest proposal version will be returned by default. Returns only
// vetted proposals.
type ProposalsDetails struct {
	Token   string `json:"token"`             // Censorship token
	Version string `json:"version,omitempty"` // Proposal version
}

// ProposalDetailsReply is used to reply to a proposal details command.
type ProposalDetailsReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// BatchProposals is used to request the proposal details for each of the
// provided censorship tokens. The returned proposals do not include the
// proposal files. Returns only vetted proposals.
type BatchProposals struct {
	Tokens []string `json:"tokens"` // Censorship tokens
}

// BatchProposalsReply is used to reply to a BatchProposals command.
type BatchProposalsReply struct {
	Proposals []ProposalRecord `json:"proposals"`
}

// BatchVoteSummary is used to request the VoteSummary for the each of the
// provided censorship tokens.
type BatchVoteSummary struct {
	Tokens []string `json:"tokens"` // Censorship tokens
}

// BatchVoteSummaryReply is used to reply to a BatchVoteSummary command.
type BatchVoteSummaryReply struct {
	BestBlock uint64                 `json:"bestblock"` // Current block height
	Summaries map[string]VoteSummary `json:"summaries"` // [token]VoteSummary
}

// SetProposalStatus is used to change the status of a proposal. Only admins
// have the ability to change a proposal's status. Some status changes, such
// as censoring a proposal, require the StatusChangeMessage to be populated
// with the reason for the status change.
type SetProposalStatus struct {
	Token               string      `json:"token"`                         // Proposal token
	ProposalStatus      PropStatusT `json:"proposalstatus"`                // New status
	StatusChangeMessage string      `json:"statuschangemessage,omitempty"` // Message associated to the status change
	Signature           string      `json:"signature"`                     // Signature of Token+string(ProposalStatus)+StatusChangeMessage
	PublicKey           string      `json:"publickey"`                     // Signature pubkey
}

// SetProposalStatusReply is used to reply to a SetProposalStatus command.
type SetProposalStatusReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// GetAllVetted retrieves vetted proposals; the maximum number returned is
// dictated by ProposalListPageSize.
//
// This command optionally takes either a Before or After parameter, which
// specify a proposal's censorship token. If After is specified, the "page"
// returned starts after the provided censorship token, when sorted in reverse
// chronological order. A simplified example is shown below.
//
// input: [5,4,3,2,1]
// after=3
// output: [2,1]
//
// If Before is specified, the "page" returned starts before the provided
// proposal censorship token, when sorted in reverse chronological order.
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
	UserListPageSize           uint     `json:"userlistpagesize"`
	MaxImages                  uint     `json:"maximages"`
	MaxImageSize               uint     `json:"maximagesize"`
	MaxMDs                     uint     `json:"maxmds"`
	MaxMDSize                  uint     `json:"maxmdsize"`
	ValidMIMETypes             []string `json:"validmimetypes"`
	MinProposalNameLength      uint     `json:"minproposalnamelength"`
	MaxProposalNameLength      uint     `json:"maxproposalnamelength"`
	PaywallEnabled             bool     `json:"paywallenabled"`
	ProposalNameSupportedChars []string `json:"proposalnamesupportedchars"`
	MaxCommentLength           uint     `json:"maxcommentlength"`
	BackendPublicKey           string   `json:"backendpublickey"`
	TokenPrefixLength          int      `json:"tokenprefixlength"`
	BuildInformation           []string `json:"buildinformation"`
	IndexFilename              string   `json:"indexfilename"`
	MinLinkByPeriod            int64    `json:"minlinkbyperiod"`
	MaxLinkByPeriod            int64    `json:"maxlinkbyperiod"`
	MinVoteDuration            uint32   `json:"minvoteduration"`
	MaxVoteDuration            uint32   `json:"maxvoteduration"`
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token            string       `json:"token"`            // Token that identifies vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []VoteOption `json:"options"`          // Vote options
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

// AuthorizeVote is used to indicate that a proposal has been finalized and
// is ready to be voted on.  The signature and public key are from the
// proposal author.  The author can revoke a previously sent vote authorization
// by setting the Action field to revoke.
type AuthorizeVote struct {
	Action    string `json:"action"`    // Authorize or revoke
	Token     string `json:"token"`     // Proposal token
	Signature string `json:"signature"` // Signature of token+version+action
	PublicKey string `json:"publickey"` // Key used for signature
}

// AuthorizeVoteReply returns a receipt if the action was successfully
// executed.
type AuthorizeVoteReply struct {
	Action  string `json:"action"`  // Authorize or revoke
	Receipt string `json:"receipt"` // Server signature of client signature
}

// StartVote starts the voting process for a proposal.
//
// THIS ROUTE HAS BEEN DEPRECATED
// A proposal vote must be initiated using the v2 StartVote route.
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

// CastVoteReply is the answer to the CastVote command. The Error and
// ErrorStatus fields will only be populated if something went wrong while
// attempting to cast the vote.
type CastVoteReply struct {
	ClientSignature string                    `json:"clientsignature"`       // Signature that was sent in
	Signature       string                    `json:"signature"`             // Signature of the ClientSignature
	Error           string                    `json:"error"`                 // Error status message
	ErrorStatus     decredplugin.ErrorStatusT `json:"errorstatus,omitempty"` // Error status code
}

// Ballot is a batch of votes that are sent to the server.
type Ballot struct {
	Votes []CastVote `json:"votes"`
}

// BallotReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// VoteResults retrieves a single proposal vote results from the server. If the
// voting period has not yet started for the given proposal a reply is returned
// with all fields set to their zero value.
type VoteResults struct{}

// VoteResultsReply returns the original proposal vote and the associated cast
// votes.
type VoteResultsReply struct {
	StartVote      StartVote      `json:"startvote"`      // Original vote
	CastVotes      []CastVote     `json:"castvotes"`      // Vote results
	StartVoteReply StartVoteReply `json:"startvotereply"` // Eligible tickets and other details
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
	CommentID   string `json:"commentid"`           // Comment ID
	Receipt     string `json:"receipt"`             // Server signature of the client Signature
	Timestamp   int64  `json:"timestamp"`           // Received UNIX timestamp
	ResultVotes int64  `json:"resultvotes"`         // Vote score
	Upvotes     uint64 `json:"upvotes,omitempty"`   // Pro votes
	Downvotes   uint64 `json:"downvotes,omitempty"` // Contra votes
	Censored    bool   `json:"censored"`            // Has this comment been censored

	// Metadata generated by www
	UserID   string `json:"userid"`   // User id
	Username string `json:"username"` // Username
}

// NewComment sends a comment from a user to a specific proposal.  Note that
// the user is implied by the session.  A parent ID of 0 indicates that the
// comment does not have a parent.  A non-zero parent ID indicates that the
// comment is a reply to an existing comment.
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
	Comments   []Comment `json:"comments"`             // Comments
	AccessTime int64     `json:"accesstime,omitempty"` // User Access Time
}

const (
	// VoteActionDown used when user votes down a comment
	VoteActionDown = "-1"
	// VoteActionUp used when user votes up a comment
	VoteActionUp = "1"
)

// LikeComment allows a user to up or down vote a comment.
type LikeComment struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Action    string `json:"action"`    // VoteActionUp or VoteActionDown above
	Signature string `json:"signature"` // Client Signature of Token+CommentID+Action
	PublicKey string `json:"publickey"` // Pubkey used for Signature
}

// LikeCommentReply returns the current up/down vote result.
type LikeCommentReply struct {
	// XXX we probably need a sequence numkber or something here and some sort of rate limit
	Total     uint64 `json:"total"`               // Total number of up and down votes
	Result    int64  `json:"result"`              // Current tally of likes, can be negative
	Upvotes   uint64 `json:"upvotes,omitempty"`   // Current tally of pro votes
	Downvotes uint64 `json:"downvotes,omitempty"` // Current tally of contra votes
	Receipt   string `json:"receipt"`             // Server signature of client signature
	Error     string `json:"error,omitempty"`     // Error if something went wrong during liking a comment
}

// CensorComment allows an admin to censor a comment. The signature and
// public key are from the admin that censored this comment.
type CensorComment struct {
	Token     string `json:"token"`     // Proposal censorship token
	CommentID string `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason the comment was censored
	Signature string `json:"signature"` // Client signature of Token+CommentID+Reason
	PublicKey string `json:"publickey"` // Pubkey used for signature
}

// CensorCommentReply returns a receipt if the comment was successfully
// censored.
type CensorCommentReply struct {
	Receipt string `json:"receipt"` // Server signature of client signature
}

// CommentLike describes the voting action an user has given
// to a comment (e.g: up or down vote)
type CommentLike struct {
	Action    string `json:"action"`    // VoteActionUp or VoteActionDown above
	CommentID string `json:"commentid"` // Comment ID
	Token     string `json:"token"`     // Censorship token
}

// UserCommentsLikes is a command to fetch all user vote actions
// on the comments of a given proposal
type UserCommentsLikes struct{}

// UserCommentsLikesReply is a reply with all user vote actions
// for the comments of a given proposal
type UserCommentsLikesReply struct {
	CommentsLikes []CommentLike `json:"commentslikes"`
}

// VoteOptionResult is a structure that describes a VotingOption along with the
// number of votes it has received
type VoteOptionResult struct {
	Option        VoteOption `json:"option"`        // Vote Option
	VotesReceived uint64     `json:"votesreceived"` // Number of votes received by the option
}

// VoteStatus is a command to fetch the the current vote status for a single
// public proposal
// *** This is deprecated by the BatchVoteSummary request. ***
type VoteStatus struct{}

// VoteStatusReply describes the vote status for a given proposal
// *** This is deprecated by the BatchVoteSummary request. ***
type VoteStatusReply struct {
	Token              string             `json:"token"`              // Censorship token
	Status             PropVoteStatusT    `json:"status"`             // Vote status (finished, started, etc)
	TotalVotes         uint64             `json:"totalvotes"`         // Proposal's total number of votes
	OptionsResult      []VoteOptionResult `json:"optionsresult"`      // VoteOptionResult for each option
	EndHeight          string             `json:"endheight"`          // Vote end height
	BestBlock          string             `json:"bestblock"`          // Current best block height
	NumOfEligibleVotes int                `json:"numofeligiblevotes"` // Total number of eligible votes
	QuorumPercentage   uint32             `json:"quorumpercentage"`   // Percent of eligible votes required for quorum
	PassPercentage     uint32             `json:"passpercentage"`     // Percent of total votes required to pass
}

// GetAllVoteStatus attempts to fetch the vote status of all public propsals
// *** This is deprecated by the BatchVoteSummary request. ***
type GetAllVoteStatus struct{}

// GetAllVoteStatusReply returns the vote status of all public proposals
// *** This is deprecated by the BatchVoteSummary request. ***
type GetAllVoteStatusReply struct {
	VotesStatus []VoteStatusReply `json:"votesstatus"` // Vote status of all public proposals
}

// UserDetails fetches a user's details by their id.
type UserDetails struct {
	UserID string `json:"userid"` // User id
}

// UserDetailsReply returns a user's details.
type UserDetailsReply struct {
	User User `json:"user"`
}

// ManageUser performs the given action on a user.
type ManageUser struct {
	UserID string            `json:"userid"` // User id
	Action UserManageActionT `json:"action"` // Action
	Reason string            `json:"reason"` // Admin reason for action
}

// ManageUserReply is the reply for the ManageUserReply command.
type ManageUserReply struct{}

// EditUser edits a user's preferences.
type EditUser struct {
	EmailNotifications *uint64 `json:"emailnotifications"` // Notify the user via emails
}

// EditUserReply is the reply for the EditUser command.
type EditUserReply struct{}

// User represents an individual user.
type User struct {
	ID                              string         `json:"id"`
	Email                           string         `json:"email"`
	Username                        string         `json:"username"`
	Admin                           bool           `json:"isadmin"`
	NewUserPaywallAddress           string         `json:"newuserpaywalladdress"`
	NewUserPaywallAmount            uint64         `json:"newuserpaywallamount"`
	NewUserPaywallTx                string         `json:"newuserpaywalltx"`
	NewUserPaywallTxNotBefore       int64          `json:"newuserpaywalltxnotbefore"`
	NewUserPaywallPollExpiry        int64          `json:"newuserpaywallpollexpiry"`
	NewUserVerificationToken        []byte         `json:"newuserverificationtoken"`
	NewUserVerificationExpiry       int64          `json:"newuserverificationexpiry"`
	UpdateKeyVerificationToken      []byte         `json:"updatekeyverificationtoken"`
	UpdateKeyVerificationExpiry     int64          `json:"updatekeyverificationexpiry"`
	ResetPasswordVerificationToken  []byte         `json:"resetpasswordverificationtoken"`
	ResetPasswordVerificationExpiry int64          `json:"resetpasswordverificationexpiry"`
	LastLoginTime                   int64          `json:"lastlogintime"`
	FailedLoginAttempts             uint64         `json:"failedloginattempts"`
	Deactivated                     bool           `json:"isdeactivated"`
	Locked                          bool           `json:"islocked"`
	Identities                      []UserIdentity `json:"identities"`
	ProposalCredits                 uint64         `json:"proposalcredits"`
	EmailNotifications              uint64         `json:"emailnotifications"` // Notify the user via emails
}

// UserIdentity represents a user's unique identity.
type UserIdentity struct {
	Pubkey string `json:"pubkey"`
	Active bool   `json:"isactive"`
}

// EditProposal attempts to edit a proposal
//
// Metadata is required to include a ProposalMetadata for all proposal
// submissions.
//
// Signature is the signature of the proposal merkle root. The merkle root
// contains the ordered files and metadata digests. The file digests are first
// in the ordering.
type EditProposal struct {
	Token     string     `json:"token"`
	Files     []File     `json:"files"`
	Metadata  []Metadata `json:"metadata"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// EditProposalReply is used to reply to the EditProposal command
type EditProposalReply struct {
	Proposal ProposalRecord `json:"proposal"`
}

// TokenInventory retrieves the censorship record tokens of all proposals in
// the inventory, categorized by stage of the voting process.
type TokenInventory struct{}

// TokenInventoryReply is used to reply to the TokenInventory command and
// returns the tokens of all proposals in the inventory. The tokens are
// categorized by stage of the voting process and sorted according to the
// rules listed below. Unvetted proposal tokens are only returned to admins.
//
// Sorted by record timestamp in descending order:
// Pre, Abandonded, Unreviewed, Censored
//
// Sorted by voting period end block height in descending order:
// Active, Approved, Rejected
type TokenInventoryReply struct {
	// Vetted
	Pre       []string `json:"pre"`       // Tokens of all props that are pre-vote
	Active    []string `json:"active"`    // Tokens of all props with an active voting period
	Approved  []string `json:"approved"`  // Tokens of all props that have been approved by a vote
	Rejected  []string `json:"rejected"`  // Tokens of all props that have been rejected by a vote
	Abandoned []string `json:"abandoned"` // Tokens of all props that have been abandoned

	// Unvetted
	Unreviewed []string `json:"unreviewed"` // Tokens of all unreviewed props
	Censored   []string `json:"censored"`   // Tokens of all censored props
}

// Websocket commands
const (
	WSCError     = "error"
	WSCPing      = "ping"
	WSCSubscribe = "subscribe"
)

// WSHeader is required to be sent before any other command. The point is to
// make decoding easier without too much magic. E.g. a ping command
// WSHeader<ping>WSPing<timestamp>
type WSHeader struct {
	Command string `json:"command"`      // Following command
	ID      string `json:"id,omitempty"` // Client setable client id
}

// WSError is a generic websocket error. It returns in ID the client side id
// and all errors it encountered in Errors.
type WSError struct {
	Command string   `json:"command,omitempty"` // Command from client
	ID      string   `json:"id,omitempty"`      // Client set client id
	Errors  []string `json:"errors"`            // Errors returned by server
}

// WSSubscribe is a client side push to tell the server what RPCs it wishes to
// subscribe to.
type WSSubscribe struct {
	RPCS []string `json:"rpcs"` // Commands that the client wants to subscribe to
}

// WSPing is a server side push to the client to see if it is still alive.
type WSPing struct {
	Timestamp int64 `json:"timestamp"` // Server side timestamp
}

// SetTOTP attempts to set a TOTP key for the chosen TOTP type (Basic/UFI2 etc).
// When the user issues this request, the server generates a new key pair for
// them and returns the key/image that will allow them to save it to their
// TOTP app of choice.  The server saves the generated TOTP secret in the
// userdb user information blob.
// If the user already has a TOTP set, they must also add a code generated from
// the currently set secret.
type SetTOTP struct {
	Type TOTPMethodT `json:"type"`
	Code string      `json:"code"`
}

// SetTOTPReply returns the generated key and image that are used to add
// the key pair to the TOTP app of choice.
type SetTOTPReply struct {
	Key   string `json:"key"`
	Image string `json:"image"` // Base64 encoded PNG
}

// VerifyTOTP must be used by a user before their TOTP is ready to use.  Once
// receiving the key/image from SetTOTP they can add it to their TOTP app.
// Upon adding it to their TOTP app, they can generate new TOTP codes at will.
type VerifyTOTP struct {
	Code string `json:"code"`
}

// VerifyTOTPReply will return an empty reply if it was successfully confirmed
// with no errors.
type VerifyTOTPReply struct {
}
