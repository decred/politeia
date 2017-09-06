package v1

import "fmt"

const (
	PoliteiaAPIVersion = 1 // API version this backend understands

	CsrfToken = "X-CSRF-Token" // CSRF token for replies

	RouteLogin  = "/login/"
	RouteLogout = "/logout/"
	RouteSecret = "/secret/"
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

type Login struct {
	Email    string
	Password string
}
