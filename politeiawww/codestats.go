// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// processUserCodeStats tries to compile code statistics based on user
// and month/year provided.
func (p *politeiawww) processUserCodeStats(ucs cms.UserCodeStats, u *user.User) (*cms.UserCodeStatsReply, error) {
	log.Tracef("processUserCodeStats")

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return nil, err
	}

	requestedUser, err := p.getCMSUserByID(ucs.UserID)
	if err != nil {
		return nil, err
	}

	// If domains don't match then just return empty reply rather than erroring.
	if !cmsUser.Admin && cmsUser.Domain != requestedUser.Domain {
		return &cms.UserCodeStatsReply{}, nil
	}

	if requestedUser.GitHubName == "" {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusMissingGithubName,
		}
	}
	cu := user.CMSCodeStatsByUserMonthYear{
		GithubName: requestedUser.GitHubName,
		Month:      int(ucs.Month),
		Year:       int(ucs.Year),
	}
	payload, err := user.EncodeCMSCodeStatsByUserMonthYear(cu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSCodeStatsByUserMonthYear,
		Payload: string(payload),
	}

	// Execute plugin command
	pcr, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	// Decode reply
	reply, err := user.DecodeCMSCodeStatsByUserMonthYearReply(
		[]byte(pcr.Payload))
	if err != nil {
		return nil, err
	}

	return &cms.UserCodeStatsReply{
		RepoStats: convertCodeStatsFromDatabase(reply.UserCodeStats),
	}, nil
}

func (p *politeiawww) processUpdateGithub(ugh cms.UpdateGithub) (*cms.UpdateGithubReply, error) {

	// make sure tracker was created, if not alert for them to check github api
	// token config
	if p.tracker == nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusTrackerNotStarted,
		}
	}
	// First update PR/Commit/Review information in Github DB
	if !ugh.OnlyCodeStats {
		err := p.tracker.Update(ugh.Organization, ugh.Repository)
		if err != nil {
			return nil, err
		}
	}
	// If Year is unset set it to previous month.
	if ugh.Month == 0 || ugh.Year == 0 {
		if time.Now().Month() == 1 {
			ugh.Month = 12
			ugh.Year = time.Now().Year() - 1
		} else {
			ugh.Month = int(time.Now().Month()) - 1
			ugh.Year = time.Now().Year()
		}
	}

	// Go fetch all Development contractors to update their stats
	cu := user.CMSUsersByDomain{
		Domain: int(cms.DomainTypeDeveloper),
	}
	payload, err := user.EncodeCMSUsersByDomain(cu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUsersByDomain,
		Payload: string(payload),
	}

	// Execute plugin command
	pcr, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	// Decode reply
	reply, err := user.DecodeCMSUsersByDomainReply([]byte(pcr.Payload))
	if err != nil {
		return nil, err
	}
	for _, u := range reply.Users {
		if u.GitHubName == "" {
			// Just move along since user has no github name set
			continue
		}

		cu := user.CMSCodeStatsByUserMonthYear{
			GithubName: u.GitHubName,
			Month:      ugh.Month,
			Year:       ugh.Year,
		}
		payload, err := user.EncodeCMSCodeStatsByUserMonthYear(cu)
		if err != nil {
			return nil, err
		}
		pc := user.PluginCommand{
			ID:      user.CMSPluginID,
			Command: user.CmdCMSCodeStatsByUserMonthYear,
			Payload: string(payload),
		}

		// Execute plugin command
		pcr, err := p.db.PluginExec(pc)
		if err != nil {
			return nil, err
		}

		// Decode reply
		reply, err := user.DecodeCMSCodeStatsByUserMonthYearReply(
			[]byte(pcr.Payload))
		if err != nil {
			return nil, err
		}

		githubUserInfo, err := p.tracker.UserInformation(ugh.Organization,
			u.GitHubName, ugh.Year, ugh.Month)
		if err != nil {
			log.Errorf("github user information failed: %v %v %v %v",
				u.GitHubName, ugh.Year, ugh.Month, err)
			continue
		}
		codeStats := convertPRsToUserCodeStats(u.GitHubName, ugh.Month,
			ugh.Year, githubUserInfo.PRs, githubUserInfo.Reviews)

		if len(reply.UserCodeStats) > 0 {
			log.Tracef("Checking update UserCodeStats: %v %v %v", u.GitHubName,
				ugh.Month, ugh.Year)
			updated := false
			// Check to see if current codestats match existing stats
			if len(codeStats) == len(reply.UserCodeStats) {
				for _, cs := range codeStats {
					found := false
					for _, ucs := range reply.UserCodeStats {
						if cs.Repository != ucs.Repository {
							continue
						} else {
							found = true
						}
						if ucs.MergedAdditions != cs.MergedAdditions ||
							ucs.MergedDeletions != cs.MergedDeletions ||
							ucs.ReviewDeletions != cs.ReviewDeletions ||
							ucs.ReviewAdditions != ucs.ReviewAdditions ||
							len(ucs.PRs) != len(cs.PRs) ||
							len(ucs.Reviews) != len(cs.Reviews) {
							updated = true
							break
						}
					}
					if !found {
						updated = true
					}
				}
			}
			if updated {
				log.Tracef("Updated UserCodeStats: %v %v %v", u.GitHubName,
					ugh.Month, ugh.Year)
				ncs := user.UpdateCMSCodeStats{
					UserCodeStats: codeStats,
				}
				payload, err = user.EncodeUpdateCMSCodeStats(ncs)
				if err != nil {
					return nil, err
				}
				pc = user.PluginCommand{
					ID:      user.CMSPluginID,
					Command: user.CmdUpdateCMSUserCodeStats,
					Payload: string(payload),
				}
				_, err = p.db.PluginExec(pc)
				if err != nil {
					return nil, err
				}
			}
			continue
		}

		log.Tracef("New UserCodeStats: %v %v %v", u.GitHubName, ugh.Month,
			ugh.Year)
		// It'll be a new entry if no existing entry had been found
		ncs := user.NewCMSCodeStats{
			UserCodeStats: codeStats,
		}

		payload, err = user.EncodeNewCMSCodeStats(ncs)
		if err != nil {
			return nil, err
		}
		pc = user.PluginCommand{
			ID:      user.CMSPluginID,
			Command: user.CmdNewCMSUserCodeStats,
			Payload: string(payload),
		}
		_, err = p.db.PluginExec(pc)
		if err != nil {
			return nil, err
		}

	}

	return &cms.UpdateGithubReply{}, nil
}
