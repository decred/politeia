package user

import (
	"encoding/json"
)

const (
	CMSPluginVersion    = "1"
	CMSPluginID         = "cms"
	CmdNewCMSUser       = "newcmsuser"
	CmdCMSUsersByDomain = "cmsusersbydomain"
)

// CMSUser represents a CMS user. It contains the standard politeiawww user
// fields as well as CMS specific user fields.
type CMSUser struct {
	User
	Domain int `json:"domain"` // Contractor domain
}

// NewCMSUser creates a new CMS user record in the user database.
type NewCMSUser struct {
	Email                     string `json:"email"`
	Username                  string `json:"username"`
	NewUserVerificationToken  []byte `json:"newuserverificationtoken"`
	NewUserVerificationExpiry int64  `json:"newuserverificationtokenexiry"`
}

// EncodeNewCMSUser encodes a NewCMSUser into a JSON byte slice.
func EncodeNewCMSUser(u NewCMSUser) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeNewCMSUser decodes JSON byte slice into a NewCMSUser.
func DecodeNewCMSUser(b []byte) (*NewCMSUser, error) {
	var u NewCMSUser

	err := json.Unmarshal(b, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// NewCMSUserReply is the reply to the NewCMSUser command.
type NewCMSUserReply struct{}

// EncodeNewCMSUserReply encodes a NewCMSUserReply into a JSON byte slice.
func EncodeNewCMSUserReply(u NewCMSUserReply) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeNewCMSUserReply decodes JSON byte slice into a NewCMSUserReply.
func DecodeNewCMSUserReply(b []byte) (*NewCMSUserReply, error) {
	var reply NewCMSUserReply

	err := json.Unmarshal(b, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// CMSUsersByDomain returns all CMS users within the provided domain.
type CMSUsersByDomain struct {
	Domain int `json:"domain"` // Contractor domain
}

// EncodeCMSUsersByDomain encodes a CMSUsersByDomain into a JSON byte slice.
func EncodeCMSUsersByDomain(u CMSUsersByDomain) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeCMSUsersByDomain decodes JSON byte slice into a CMSUsersByDomain.
func DecodeCMSUsersByDomain(b []byte) (*CMSUsersByDomain, error) {
	var u CMSUsersByDomain

	err := json.Unmarshal(b, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// CMSUsersByDomainReply is the reply to the CMSUsersByDomain command.
type CMSUsersByDomainReply struct {
	Users []CMSUser `json:"users"`
}

// EncodeCMSUsersByDomainReply encodes a CMSUsersByDomainReply into a JSON
// byte slice.
func EncodeCMSUsersByDomainReply(u CMSUsersByDomainReply) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeCMSUsersByDomainReply decodes JSON byte slice into a
// CMSUsersByDomainReply.
func DecodeCMSUsersByDomainReply(b []byte) (*CMSUsersByDomainReply, error) {
	var reply CMSUsersByDomainReply

	err := json.Unmarshal(b, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}
