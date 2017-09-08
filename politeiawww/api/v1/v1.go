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
	PoliteiaAPIRoute = fmt.Sprintf("/api/v%v", PoliteiaWWWAPIVersion)

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

// NewUser ...
type NewUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// NewUserReply ...
type NewUserReply struct {
	VerificationToken string `json:"verificationtoken"`
}

// VerifyNewUser ...
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
