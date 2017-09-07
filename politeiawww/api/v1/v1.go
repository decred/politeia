package v1

import "fmt"

const (
	PoliteiaAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteNewUser = "/user/new"
	RouteVerifyNewUser = "/user/verify"
	RouteLogin   = "/login/"
	RouteLogout  = "/logout/"
	RouteSecret  = "/secret/"

	VerificationTokenSize   = 32 // Size of verification token in bytes
	VerificationExpiryHours = 48 // Number of hours before the verification token expires
)

var (
	// politeiaAPIRoute is the prefix to the API route
	PoliteiaAPIRoute = fmt.Sprintf("/api/v%v", PoliteiaAPIVersion)

	CookieSession = "session"
)

// Version command is used to determine the version of the API this backend
// understands and additionally it provides the route to said API.
type Version struct {
	Version uint   // politeia WWW API version
	Route   string // prefix to API calls
}

type NewUser struct {
	Email    string
	Password string
}

type NewUserReply struct {
	VerificationToken string // Token used to verify the user's email address
}

type VerifyNewUser struct {
	Email             string
	VerificationToken string // Same token returned in NewUserReply
}

type Login struct {
	Email    string
	Password string
}
