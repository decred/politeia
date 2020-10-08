// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

var (
	userCodeStatsRangeLimit = time.Minute * 60 * 24 * 7 * 26 // 6 months in minutes == 60mins * 24hrs * 7days * 26weeks
)

// processUserCodeStats tries to compile code statistics based on user
// and month/year provided.
func (p *politeiawww) processUserCodeStats(ucs cms.UserCodeStats, u *user.User) (*cms.UserCodeStatsReply, error) {
	log.Tracef("processUserCodeStats")

	// Require start time to be entered
	if ucs.StartTime == 0 {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDatesRequested,
		}
	}
	startDate := time.Unix(ucs.StartTime, 0).UTC()
	var endDate time.Time
	if ucs.EndTime == 0 {
		// If endtime is unset just use start time plus a minute, this will
		// cause it to reply with just the month of the start time.
		endDate = startDate
	} else {
		endDate = time.Unix(ucs.EndTime, 0).UTC()
	}

	// Check to make sure time range requested is not greater than 6 months OR
	// End time is AFTER Start time
	if endDate.Before(startDate) ||
		endDate.Sub(startDate) > userCodeStatsRangeLimit {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDatesRequested,
		}
	}

	requestingUser, err := p.getCMSUserByID(u.ID.String())
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
	if !requestingUser.Admin && requestingUser.Domain != requestedUser.Domain {
		return &cms.UserCodeStatsReply{}, nil
	}

	if requestedUser.GitHubName == "" {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusMissingCodeStatsUsername,
		}
	}

	allRepoStats := make([]cms.CodeStats, 0, 1048)
	// Run until start date is after end date, it's incremented by a month
	// a the end of the loop.
	for !startDate.After(endDate) {
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
		allRepoStats = append(allRepoStats,
			convertCodeStatsFromDatabase(reply.UserCodeStats)...)

		startDate = time.Date(startDate.Year(), startDate.Month()+1,
			startDate.Day(), startDate.Hour(), startDate.Minute(), 0, 0,
			time.UTC)
	}
	return &cms.UserCodeStatsReply{
		RepoStats: allRepoStats,
	}, nil
}

func (p *politeiawww) updateCodeStats(org string, repos []string, start, end int64) error {

	// make sure tracker was created, if not alert for them to check github api
	// token config
	if p.tracker == nil {
		return fmt.Errorf("code tracker not running")
	}

	p.tracker.Update(org, repos, start, end)

	// Go fetch all Development contractors to update their stats
	cu := user.CMSUsersByDomain{
		Domain: int(cms.DomainTypeDeveloper),
	}
	payload, err := user.EncodeCMSUsersByDomain(cu)
	if err != nil {
		return err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUsersByDomain,
		Payload: string(payload),
	}

	// Execute plugin command
	pcr, err := p.db.PluginExec(pc)
	if err != nil {
		return err
	}

	// Decode reply
	reply, err := user.DecodeCMSUsersByDomainReply([]byte(pcr.Payload))
	if err != nil {
		return err
	}

	currentMonth := int(time.Now().Month())
	currentYear := time.Now().Year()

	for _, u := range reply.Users {
		if u.GitHubName == "" {
			// Just move along since user has no github name set
			continue
		}

		cu := user.CMSCodeStatsByUserMonthYear{
			GithubName: u.GitHubName,
			Month:      currentMonth,
			Year:       currentYear,
		}
		payload, err := user.EncodeCMSCodeStatsByUserMonthYear(cu)
		if err != nil {
			return err
		}
		pc := user.PluginCommand{
			ID:      user.CMSPluginID,
			Command: user.CmdCMSCodeStatsByUserMonthYear,
			Payload: string(payload),
		}

		// Execute plugin command
		pcr, err := p.db.PluginExec(pc)
		if err != nil {
			return err
		}

		// Decode reply
		reply, err := user.DecodeCMSCodeStatsByUserMonthYearReply(
			[]byte(pcr.Payload))
		if err != nil {
			return err
		}

		githubUserInfo, err := p.tracker.UserInfo(org,
			u.GitHubName, currentYear, currentMonth)
		if err != nil {
			log.Errorf("github user information failed: %v %v %v %v",
				u.GitHubName, currentYear, currentMonth, err)
			continue
		}

		codeStats := convertPRsToUserCodeStats(u.GitHubName, currentYear,
			currentMonth, githubUserInfo.MergedPRs, githubUserInfo.UpdatedPRs,
			githubUserInfo.Reviews)

		if len(reply.UserCodeStats) > 0 {
			log.Tracef("Checking update UserCodeStats: %v %v %v", u.GitHubName,
				currentYear, currentMonth)
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
					currentYear, currentMonth)
				ncs := user.UpdateCMSCodeStats{
					UserCodeStats: codeStats,
				}
				payload, err = user.EncodeUpdateCMSCodeStats(ncs)
				if err != nil {
					return err
				}
				pc = user.PluginCommand{
					ID:      user.CMSPluginID,
					Command: user.CmdUpdateCMSUserCodeStats,
					Payload: string(payload),
				}
				_, err = p.db.PluginExec(pc)
				if err != nil {
					return err
				}
			}
			continue
		}

		log.Tracef("New UserCodeStats: %v %v %v", u.GitHubName, currentYear,
			currentMonth)
		// It'll be a new entry if no existing entry had been found
		ncs := user.NewCMSCodeStats{
			UserCodeStats: codeStats,
		}

		payload, err = user.EncodeNewCMSCodeStats(ncs)
		if err != nil {
			return err
		}
		pc = user.PluginCommand{
			ID:      user.CMSPluginID,
			Command: user.CmdNewCMSUserCodeStats,
			Payload: string(payload),
		}
		_, err = p.db.PluginExec(pc)
		if err != nil {
			return err
		}

	}

	return nil
}

// Seconds Minutes Hours Days Months DayOfWeek
const codeStatsSchedule = "0 0 1 * *" // Check at 12:00 AM on 1st day every month

func (p *politeiawww) startCodeStatsCron() {
	log.Infof("Starting cron for code stats update")
	// Launch invoice notification cron job
	err := p.cron.AddFunc(codeStatsSchedule, func() {
		log.Infof("Running code stats cron")
		// End time for codestats is when the cron starts.
		end := time.Now()
		// Start time is 1 month and 1 day prior to the current time.
		start := time.Date(end.Year(), end.Month()-1, end.Day()-1, end.Hour(),
			end.Minute(), end.Second(), 0, end.Location())
		err := p.updateCodeStats(p.cfg.CodeStatOrganization,
			p.cfg.CodeStatRepos, start.Unix(), end.Unix())
		if err != nil {
			log.Errorf("erroring updating code stats %v", err)
		}

	})
	if err != nil {
		log.Errorf("Error running codestats cron: %v", err)
	}
}
