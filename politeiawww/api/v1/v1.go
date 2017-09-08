package v1

import "fmt"

const (
	PoliteiaAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteNewUser       = "/user/new/"
	RouteVerifyNewUser = "/user/verify/"
	RouteLogin         = "/login/"
	RouteLogout        = "/logout/"
	RouteSecret        = "/secret/"

	VerificationTokenSize   = 32 // Size of verification token in bytes
	VerificationExpiryHours = 48 // Number of hours before the verification token expires
)

var (
	// PoliteiaAPIRoute is the prefix to the API route
	PoliteiaAPIRoute = fmt.Sprintf("/api/v%v", PoliteiaAPIVersion)

	CookieSession = "session"
)

// Version command is used to determine the version of the API this backend
// understands and additionally it provides the route to said API.
type Version struct {
	Version uint   `json:"version"` // politeia WWW API version
	Route   string `json:"route"`   // prefix to API calls
}

type NewUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type NewUserReply struct {
	VerificationToken string `json:"verificationToken"` // Token used to verify the user's email address
}

type VerifyNewUser struct {
	Email             string `json:"email"`
	VerificationToken string `json:"verificationToken"` // Same token returned in NewUserReply
}

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
