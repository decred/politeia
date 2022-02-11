package mysql

import (
	"strings"

	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/uuid"
)

func convertCMSUserFromDatabase(cu CMSUser) (*user.CMSUser, error) {
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

func convertCMSUsersFromDatabase(cu []CMSUser) ([]user.CMSUser, error) {
	users := make([]user.CMSUser, 0, len(cu))
	for _, v := range cu {
		u, err := convertCMSUserFromDatabase(v)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, nil
}

func convertCodestatsFromDatabase(cs CMSCodeStats) user.CodeStats {
	prs := strings.Split(cs.PRs, ",")
	prsSlice := make([]string, 0, len(prs))
	reviews := strings.Split(cs.Reviews, ",")
	reviewsSlice := make([]string, 0, len(reviews))
	commits := strings.Split(cs.Commits, ",")
	commitsSlice := make([]string, 0, len(commits))
	for _, pr := range prs {
		if pr == "" {
			continue
		}
		prsSlice = append(prsSlice, strings.TrimSpace(pr))
	}
	for _, review := range reviews {
		if review == "" {
			continue
		}
		reviewsSlice = append(reviewsSlice, strings.TrimSpace(review))
	}
	for _, commit := range commits {
		if commit == "" {
			continue
		}
		commitsSlice = append(commitsSlice, strings.TrimSpace(commit))
	}
	return user.CodeStats{
		ID:               cs.ID,
		GitHubName:       cs.GitHubName,
		Repository:       cs.Repository,
		Month:            cs.Month,
		Year:             cs.Year,
		PRs:              prsSlice,
		Reviews:          reviewsSlice,
		Commits:          commitsSlice,
		MergedAdditions:  cs.MergedAdditions,
		MergedDeletions:  cs.MergedDeletions,
		UpdatedAdditions: cs.UpdatedAdditions,
		UpdatedDeletions: cs.UpdatedDeletions,
		ReviewAdditions:  cs.ReviewAdditions,
		ReviewDeletions:  cs.ReviewDeletions,
		CommitAdditions:  cs.CommitAdditions,
		CommitDeletions:  cs.CommitDeletions,
	}
}
