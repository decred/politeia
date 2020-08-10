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

var (
	month31Days = map[int]bool{
		0:  true,
		2:  true,
		4:  true,
		6:  true,
		7:  true,
		9:  true,
		11: true,
	}
)

// processUserCodeStats tries to compile code statistics based on user
// and month/year provided.
func (p *politeiawww) processUserCodeStats(ucs cms.UserCodeStats, u *user.User) (*cms.UserCodeStatsReply, error) {
	log.Tracef("processUserCodeStats")

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err == user.ErrUserNotFound {
		log.Debugf("processUserCodeStats failure for %v: cmsuser not found",
			u.ID.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotFound,
		}
	} else if err != nil {
		log.Debugf("processUserCodeStats failure for %v: getCMSUser %v",
			ucs.UserID)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotFound,
		}
	}

	requestedUser, err := p.getCMSUserByID(ucs.UserID)
	if err == user.ErrUserNotFound {
		log.Debugf("processUserCodeStats failure for %v: cmsuser not found",
			ucs.UserID)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotFound,
		}
	} else if err != nil {
		log.Debugf("processUserCodeStats failure for %v: getCMSUser %v",
			ucs.UserID, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotFound,
		}
	}

	// If domains don't match then just return empty reply rather than erroring.
	if !cmsUser.Admin && cmsUser.Domain != requestedUser.Domain {
		return &cms.UserCodeStatsReply{}, nil
	}

	if requestedUser.GitHubName == "" {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusMissingCodeStatsUsername,
		}
	}
	startDate := time.Unix(ucs.StartTime, 0)
	if ucs.StartTime == 0 {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDatesRequested,
		}
	}
	if ucs.StartTime > ucs.EndTime {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDatesRequested,
		}
	}
	var endDate time.Time
	if ucs.EndTime == 0 {
		endDate = startDate
	} else {
		endDate = time.Unix(ucs.EndTime, 0).Add(time.Minute)
	}

	allRepoStats := make([]cms.CodeStats, 0, 1048)
	for startDate.Before(endDate) {
		month := startDate.Month()
		year := startDate.Year()

		cu := user.CMSCodeStatsByUserMonthYear{
			GithubName: requestedUser.GitHubName,
			Month:      int(month),
			Year:       year,
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
		allRepoStats = append(allRepoStats, convertCodeStatsFromDatabase(reply.UserCodeStats)...)

		// Figure out if month is 31 days or 30
		if ok := month31Days[int(month)]; ok {
			startDate = startDate.Add(time.Minute * 60 * 24 * 31) // 31 Days
		} else {
			startDate = startDate.Add(time.Minute * 60 * 24 * 30) // 30 Days
		}
	}
	return &cms.UserCodeStatsReply{
		RepoStats: allRepoStats,
	}, nil
}

func (p *politeiawww) processUpdateCodeStats(ugh cms.UpdateCodeStats) (*cms.UpdateCodeStatsReply, error) {

	// make sure tracker was created, if not alert for them to check github api
	// token config
	if p.tracker == nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusTrackerNotStarted,
		}
	}

	// If month and year are not both set, then update tracker data before
	// updating users' codestats, then update the previous month's codestats.
	if ugh.Month == 0 && ugh.Year == 0 {
		err := p.tracker.Update(ugh.Organization, ugh.Repository)
		if err != nil {
			return nil, err
		}
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

		githubUserInfo, err := p.tracker.UserInfo(ugh.Organization,
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
			} else {
				updated = true
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

	return &cms.UpdateCodeStatsReply{}, nil
}
