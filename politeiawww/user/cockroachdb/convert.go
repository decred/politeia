package cockroachdb

import "github.com/thi4go/politeia/politeiawww/user"

func convertIdentityFromUser(id user.Identity) Identity {
	return Identity{
		PublicKey:   id.String(),
		Activated:   id.Activated,
		Deactivated: id.Deactivated,
	}
}

func convertIdentitiesFromUser(ids []user.Identity) []Identity {
	s := make([]Identity, 0, len(ids))
	for _, v := range ids {
		s = append(s, convertIdentityFromUser(v))
	}
	return s
}

func convertUserFromUser(u user.User, blob []byte) User {
	return User{
		ID:         u.ID,
		Username:   u.Username,
		Identities: convertIdentitiesFromUser(u.Identities),
		Blob:       blob,
	}
}
