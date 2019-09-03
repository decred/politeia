package user

import (
	"encoding/json"

	"github.com/google/uuid"
)

const (
	CMSPluginVersion    = "1"
	CMSPluginID         = "cms"
	CmdNewCMSUser       = "newcmsuser"
	CmdCMSUsersByDomain = "cmsusersbydomain"
	CmdUpdateCMSUser    = "updatecmsuser"
	CmdCMSUserByID      = "cmsuserbyid"
)

// CMSUser represents a CMS user. It contains the standard politeiawww user
// fields as well as CMS specific user fields.
type CMSUser struct {
	User
	Domain             int    `json:"domain"` // Contractor domain
	GitHubName         string `json:"githubname"`
	MatrixName         string `json:"matrixname"`
	ContractorType     int    `json:"contractortype"`
	ContractorName     string `json:"contractorname"`
	ContractorLocation string `json:"contractorlocation"`
	ContractorContact  string `json:"contractorcontact"`
	SupervisorUserID   string `json:"supervisoruserid"`
}

// NewCMSUser creates a new CMS user record in the user database.
type NewCMSUser struct {
	Email                     string `json:"email"`
	Username                  string `json:"username"`
	NewUserVerificationToken  []byte `json:"newuserverificationtoken"`
	NewUserVerificationExpiry int64  `json:"newuserverificationtokenexiry"`
	ContractorType            int    `json:"contractortype"`
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

// UpdateCMSUser creates a new CMS user record in the user database.
type UpdateCMSUser struct {
	ID                 uuid.UUID `json:"id"`
	Domain             int       `json:"domain"` // Contractor domain
	GitHubName         string    `json:"githubname"`
	MatrixName         string    `json:"matrixname"`
	ContractorType     int       `json:"contractortype"`
	ContractorName     string    `json:"contractorname"`
	ContractorLocation string    `json:"contractorlocation"`
	ContractorContact  string    `json:"contractorcontact"`
	SupervisorUserID   string    `json:"supervisoruserid"`
}

// EncodeUpdateCMSUser encodes a UpdateCMSUser into a JSON byte slice.
func EncodeUpdateCMSUser(u UpdateCMSUser) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeUpdateCMSUser decodes JSON byte slice into a UpdateCMSUser.
func DecodeUpdateCMSUser(b []byte) (*UpdateCMSUser, error) {
	var u UpdateCMSUser

	err := json.Unmarshal(b, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// UpdateCMSUserReply is the reply to the UpdateCMSUser command.
type UpdateCMSUserReply struct{}

// EncodeUpdateCMSUserReply encodes a UpdateCMSUserReply into a JSON byte slice.
func EncodeUpdateCMSUserReply(u UpdateCMSUserReply) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeUpdateCMSUserReply decodes JSON byte slice into a UpdateCMSUserReply.
func DecodeUpdateCMSUserReply(b []byte) (*UpdateCMSUserReply, error) {
	var reply UpdateCMSUserReply

	err := json.Unmarshal(b, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// CMSUserByID returns CMS User with the matching user ID.
type CMSUserByID struct {
	ID string `json:"id"` // Contractor user id
}

// EncodeCMSUserByID encodes a CMSUserByID into a JSON byte slice.
func EncodeCMSUserByID(u CMSUserByID) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeCMSUserByID decodes JSON byte slice into a CMSUserByID.
func DecodeCMSUserByID(b []byte) (*CMSUserByID, error) {
	var u CMSUserByID

	err := json.Unmarshal(b, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// CMSUserByIDReply is the reply to the CMSUserByID command.
type CMSUserByIDReply struct {
	User *CMSUser `json:"user"`
}

// EncodeCMSUserByIDReply encodes a CMSUserByIDReply into a JSON
// byte slice.
func EncodeCMSUserByIDReply(u CMSUserByIDReply) ([]byte, error) {
	return json.Marshal(u)
}

// DecodeCMSUserByIDReply decodes JSON byte slice into a
// CMSUserByIDReply.
func DecodeCMSUserByIDReply(b []byte) (*CMSUserByIDReply, error) {
	var reply CMSUserByIDReply

	err := json.Unmarshal(b, &reply)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}
