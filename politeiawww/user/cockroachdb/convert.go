package cockroachdb

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

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

func (c *cockroachdb) convertCMSUserFromDatabase(cu CMSUser) (*user.CMSUser, error) {
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
	b, _, err := c.decrypt(cu.User.Blob)
	if err != nil {
		return nil, err
	}
	usr, err := user.DecodeUser(b)
	if err != nil {
		return nil, err
	}
	u.User = *usr
	return &u, nil
}

func (c *cockroachdb) convertCMSUsersFromDatabase(cu []CMSUser) ([]user.CMSUser, error) {
	users := make([]user.CMSUser, 0, len(cu))
	for _, v := range cu {
		u, err := c.convertCMSUserFromDatabase(v)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, nil
}

func convertCodestatsToDatabase(cs user.CodeStats) CMSCodeStats {
	prs := ""
	reviews := ""
	commits := ""
	for i, pr := range cs.PRs {
		if i < len(cs.PRs)-1 {
			prs += pr + ","
		} else {
			prs += pr
		}
	}
	for i, review := range cs.Reviews {
		if i < len(cs.Reviews)-1 {
			reviews += review + ","
		} else {
			reviews += review
		}
	}
	for i, commit := range cs.Commits {
		if i < len(cs.Commits)-1 {
			commits += commit + ","
		} else {
			commits += commit
		}
	}
	id := fmt.Sprintf("%v-%v-%v-%v", cs.GitHubName, cs.Repository,
		strconv.Itoa(cs.Month), strconv.Itoa(cs.Year))
	return CMSCodeStats{
		ID:               id,
		GitHubName:       cs.GitHubName,
		Repository:       cs.Repository,
		Month:            cs.Month,
		Year:             cs.Year,
		PRs:              prs,
		Reviews:          reviews,
		Commits:          commits,
		MergedAdditions:  cs.MergedAdditions,
		MergedDeletions:  cs.MergedDeletions,
		UpdatedAdditions: cs.UpdatedAdditions,
		UpdatedDeletions: cs.UpdatedDeletions,
		ReviewAdditions:  cs.ReviewAdditions,
		ReviewDeletions:  cs.ReviewDeletions,
		CommitAdditons:   cs.CommitAdditions,
		CommitDeletions:  cs.CommitDeletions,
	}
}

func convertCodestatsFromDatabase(cs CMSCodeStats) user.CodeStats {
	prs := strings.Split(cs.PRs, ",")
	reviews := strings.Split(cs.Reviews, ",")
	commits := strings.Split(cs.Commits, ",")
	return user.CodeStats{
		ID:               cs.ID,
		GitHubName:       cs.GitHubName,
		Repository:       cs.Repository,
		Month:            cs.Month,
		Year:             cs.Year,
		PRs:              prs,
		Reviews:          reviews,
		Commits:          commits,
		MergedAdditions:  cs.MergedAdditions,
		MergedDeletions:  cs.MergedDeletions,
		UpdatedAdditions: cs.UpdatedAdditions,
		UpdatedDeletions: cs.UpdatedDeletions,
		ReviewAdditions:  cs.ReviewAdditions,
		ReviewDeletions:  cs.ReviewDeletions,
		CommitAdditions:  cs.CommitAdditons,
		CommitDeletions:  cs.CommitDeletions,
	}
}
