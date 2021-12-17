package mysql

import (
	"strings"

	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/uuid"
)

func (m *mysql) convertCMSUserFromDatabase(cu CMSUser) (*user.CMSUser, error) {
	proposalsOwned := strings.Split(cu.ProposalsOwned, ",")
	superUserIds := strings.Split(cu.SupervisorUserID, ",")
	parsedUUIds := make([]uuid.UUID, 0, len(superUserIds))
	proposalsSlice := make([]string, 0, len(proposalsOwned))
	for _, proposal := range proposalsOwned {
		if proposal == "" {
			continue
		}
		proposalsSlice = append(proposalsSlice, strings.TrimSpace(proposal))
	}
	for _, userIds := range superUserIds {
		if userIds == "" {
			continue
		}
		parsed, err := uuid.Parse(strings.TrimSpace(userIds))
		if err != nil {
			return nil, err
		}
		parsedUUIds = append(parsedUUIds, parsed)
	}
	u := user.CMSUser{
		Domain:             cu.Domain,
		GitHubName:         cu.GitHubName,
		MatrixName:         cu.MatrixName,
		ContractorType:     cu.ContractorType,
		ContractorName:     cu.ContractorName,
		ContractorLocation: cu.ContractorLocation,
		ContractorContact:  cu.ContractorContact,
		SupervisorUserIDs:  parsedUUIds,
		ProposalsOwned:     proposalsSlice,
	}
	/*
		 XXX What to do here?
			b, _, err := m.decrypt(cu.User.Blob)
			if err != nil {
				return nil, err
			}
			usr, err := user.DecodeUser(b)
			if err != nil {
				return nil, err
			}
			u.User = *usr
	*/
	return &u, nil
}

func (m *mysql) convertCMSUsersFromDatabase(cu []CMSUser) ([]user.CMSUser, error) {
	users := make([]user.CMSUser, 0, len(cu))
	for _, v := range cu {
		u, err := m.convertCMSUserFromDatabase(v)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, nil
}
