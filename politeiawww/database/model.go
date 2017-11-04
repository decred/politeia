package database

// User record.
type User struct {
	ID                              uint64 `json:"id,omitempty"`                   // Unique id
	Email                           string `json:"email" gorm:"not null; unique"`  // User email address, also the lookup key.
	HashedPassword                  []byte `json:"hashedpassword" gorm:"not null"` // Blowfish hash
	Admin                           bool   // Is user an admin
	NewUserVerificationToken        []byte // Token used to verify user's email address (if populated).
	NewUserVerificationExpiry       int64  // Unix time representing the moment that the token expires.
	ResetPasswordVerificationToken  []byte
	ResetPasswordVerificationExpiry int64
}
