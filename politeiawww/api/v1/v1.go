package v1

import "fmt"

const (
	PoliteiaWWWAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteNewUser       = "/user/new/"
	RouteVerifyNewUser = "/user/verify/"
	RouteLogin         = "/login/"
	RouteLogout        = "/logout/"
	RouteSecret        = "/secret/"

	// Size of verification token in bytes
	VerificationTokenSize = 32

	// Number of hours before the verification token expires
	VerificationExpiryHours = 48
)

var (
	// PoliteiaWWWAPIRoute is the prefix to the API route
	PoliteiaWWWAPIRoute = fmt.Sprintf("/api/v%v", PoliteiaWWWAPIVersion)

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

// NewUserReply is used to reply to the NewUser command with
// the verification token.
type NewUserReply struct {
	ID                uint64 `json:"id"`
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
