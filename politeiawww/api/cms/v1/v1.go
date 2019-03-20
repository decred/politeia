package v1

const (

	// Contractor Management Routes

	RouteInviteNewUser = "/invite"
	RouteRegisterUser  = "/register"
)

/// Contractor Management System Routes

// InviteNewUser is used to request that a new user invitation be sent via email.
// If successful, the user will require verification before being able to login.
type InviteNewUser struct {
	Email string `json:"email"`
}

// InviteNewUserReply responds with the verification token for the user
// (if an email server is not set up).
type InviteNewUserReply struct {
	VerificationToken string `json:"verificationtoken"`
}

// RegisterUser is used by an contractor that has been invited to join the
// Contractor Management System
type RegisterUser struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	Name              string `json:"name"`       // User's full name
	Location          string `json:"location"`   // User's physical location
	ExtendedPublicKey string `json:"xpublickey"` // Extended public key for user's payment account
	VerificationToken string `json:"verificationtoken"`
	PublicKey         string `json:"publickey"`
}

// RegisterUserReply replies to Register with no properties, if successful.
type RegisterUserReply struct{}
