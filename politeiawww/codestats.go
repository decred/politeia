// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/codetracker"
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

func (p *politeiawww) updateCodeStats(skipStartupSync bool, repos []string, start, end int64) error {

	// make sure tracker was created, if not alert for them to check github api
	// token config
	if p.tracker == nil {
		return fmt.Errorf("code tracker not running")
	}
	if !skipStartupSync {
		p.tracker.Update(repos, start, end)
	}

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

	now := time.Now()
	// Whenever this runs we want to calculate the stats for the previous month.
	// For example if it runs on Nov 1st it will calculate stats for October.
	// If it is started on Oct. 15th it will calculate stats for September.
	lastMonth := time.Date(now.Year(), now.Month()-1, now.Day(), now.Hour(),
		now.Minute(), 0, 0, now.Location())

	currentMonth := int(lastMonth.Month())
	currentYear := lastMonth.Year()

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

		githubUserInfo, err := p.tracker.UserInfo(u.GitHubName, currentYear,
			currentMonth)
		if err != nil {
			log.Errorf("github user information failed: %v %v %v %v",
				u.GitHubName, currentYear, currentMonth, err)
			continue
		}

		codeStats := convertCodeTrackerToUserCodeStats(u.GitHubName, currentYear,
			currentMonth, githubUserInfo)

		if len(reply.UserCodeStats) > 0 {
			log.Tracef("Checking update UserCodeStats: %v %v %v", u.GitHubName,
				currentYear, currentMonth)
			err = p.checkUpdateCodeStats(reply.UserCodeStats, codeStats)
			if err != nil {
				return err
			}
			return nil
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

func (p *politeiawww) checkUpdateCodeStats(existing, new []user.CodeStats) error {
	// Check to see if current codestats match existing stats.
	updated := false
	// If the length of existing and new, differ that means it's been updated.
	if len(existing) == len(new) {
		// Loop through all newly received code stats
		for _, cs := range new {
			found := false
			for _, ucs := range existing {
				if cs.Repository != ucs.Repository {
					continue
				}
				found = true
				// Repositories match so check stats to see if anything has
				// been updated.
				if ucs.MergedAdditions != cs.MergedAdditions ||
					ucs.MergedDeletions != cs.MergedDeletions ||
					ucs.ReviewDeletions != cs.ReviewDeletions ||
					ucs.ReviewAdditions != cs.ReviewAdditions ||
					ucs.UpdatedAdditions != cs.UpdatedAdditions ||
					ucs.UpdatedDeletions != cs.UpdatedDeletions ||
					ucs.CommitAdditions != cs.CommitAdditions ||
					ucs.CommitDeletions != cs.CommitDeletions ||
					len(ucs.PRs) != len(cs.PRs) ||
					len(ucs.Reviews) != len(cs.Reviews) ||
					len(ucs.Commits) != len(cs.Commits) {
					updated = true
					break
				}
			}
			// The new repository wasn't found so update to the new codestats.
			if !found {
				updated = true
				break
			}
		}
	} else {
		// Lengths of new and exiting code stats differ, so update to new.
		updated = true
	}
	if !updated {
		return nil
	}

	// Prepare payload and send to user database plugin.
	ncs := user.UpdateCMSCodeStats{
		UserCodeStats: new,
	}
	payload, err := user.EncodeUpdateCMSCodeStats(ncs)
	if err != nil {
		return err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUserCodeStats,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return err

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
		err := p.updateCodeStats(false, p.cfg.CodeStatRepos, start.Unix(),
			end.Unix())
		if err != nil {
			log.Errorf("erroring updating code stats %v", err)
		}

	})
	if err != nil {
		log.Errorf("Error running codestats cron: %v", err)
	}
}

func convertCodeStatsFromDatabase(userCodeStats []user.CodeStats) []cms.CodeStats {
	cmsCodeStats := make([]cms.CodeStats, 0, len(userCodeStats))
	for _, codeStat := range userCodeStats {
		prs := make([]string, 0, len(codeStat.PRs))
		reviews := make([]string, 0, len(codeStat.Reviews))
		commits := make([]string, 0, len(codeStat.Commits))
		for _, pr := range codeStat.PRs {
			if pr == "" {
				continue
			}
			prs = append(prs, pr)
		}
		for _, review := range codeStat.Reviews {
			if review == "" {
				continue
			}
			reviews = append(reviews, review)
		}
		for _, commit := range codeStat.Commits {
			if commit == "" {
				continue
			}
			commits = append(commits, commit)
		}
		cmsCodeStat := cms.CodeStats{
			Month:            codeStat.Month,
			Year:             codeStat.Year,
			Repository:       codeStat.Repository,
			PRs:              prs,
			Reviews:          reviews,
			Commits:          commits,
			MergedAdditions:  codeStat.MergedAdditions,
			MergedDeletions:  codeStat.MergedDeletions,
			UpdatedAdditions: codeStat.UpdatedAdditions,
			UpdatedDeletions: codeStat.UpdatedDeletions,
			ReviewAdditions:  codeStat.ReviewAdditions,
			ReviewDeletions:  codeStat.ReviewDeletions,
			CommitAdditions:  codeStat.CommitAdditions,
			CommitDeletions:  codeStat.CommitDeletions,
		}
		cmsCodeStats = append(cmsCodeStats, cmsCodeStat)
	}
	return cmsCodeStats
}

func convertCodeTrackerToUserCodeStats(githubName string, year, month int, userInfo *codetracker.UserInformationResult) []user.CodeStats {
	mergedPRs := userInfo.MergedPRs
	updatedPRs := userInfo.UpdatedPRs
	commits := userInfo.Commits
	reviews := userInfo.Reviews
	repoStats := make([]user.CodeStats, 0, 1048) // PNOOMA
	for _, pr := range mergedPRs {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == pr.Repository {
				repoFound = true
				repoStat.PRs = append(repoStat.PRs, pr.URL)
				repoStat.MergedAdditions += pr.Additions
				repoStat.MergedDeletions += pr.Deletions
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			id := fmt.Sprintf("%v-%v-%v-%v", githubName, pr.Repository,
				strconv.Itoa(year), strconv.Itoa(month))
			repoStat := user.CodeStats{
				ID:              id,
				GitHubName:      githubName,
				Month:           month,
				Year:            year,
				PRs:             []string{pr.URL},
				Repository:      pr.Repository,
				MergedAdditions: pr.Additions,
				MergedDeletions: pr.Deletions,
			}
			repoStats = append(repoStats, repoStat)
		}
	}
	for _, pr := range updatedPRs {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == pr.Repository {
				repoFound = true
				repoStat.PRs = append(repoStat.PRs, pr.URL)
				repoStat.UpdatedAdditions += pr.Additions
				repoStat.UpdatedDeletions += pr.Deletions
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			id := fmt.Sprintf("%v-%v-%v-%v", githubName, pr.Repository,
				strconv.Itoa(year), strconv.Itoa(month))
			repoStat := user.CodeStats{
				ID:               id,
				GitHubName:       githubName,
				Month:            month,
				Year:             year,
				PRs:              []string{pr.URL},
				Repository:       pr.Repository,
				UpdatedAdditions: pr.Additions,
				UpdatedDeletions: pr.Deletions,
			}
			repoStats = append(repoStats, repoStat)
		}
	}
	for _, review := range reviews {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == review.Repository {
				repoFound = true
				repoStat.ReviewAdditions += int64(review.Additions)
				repoStat.ReviewDeletions += int64(review.Deletions)
				repoStat.Reviews = append(repoStat.Reviews, review.URL)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			id := fmt.Sprintf("%v-%v-%v-%v", githubName, review.Repository,
				strconv.Itoa(year), strconv.Itoa(month))
			repoStat := user.CodeStats{
				ID:              id,
				GitHubName:      githubName,
				Month:           month,
				Year:            year,
				Repository:      review.Repository,
				ReviewAdditions: int64(review.Additions),
				ReviewDeletions: int64(review.Deletions),
				Reviews:         []string{review.URL},
			}
			repoStats = append(repoStats, repoStat)
		}
	}

	for _, commit := range commits {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == commit.Repository {
				repoFound = true
				repoStat.CommitAdditions += int64(commit.Additions)
				repoStat.CommitDeletions += int64(commit.Deletions)
				repoStat.Commits = append(repoStat.Commits, commit.URL)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			id := fmt.Sprintf("%v-%v-%v-%v", githubName, commit.Repository,
				strconv.Itoa(year), strconv.Itoa(month))
			repoStat := user.CodeStats{
				ID:              id,
				GitHubName:      githubName,
				Month:           month,
				Year:            year,
				Repository:      commit.Repository,
				CommitAdditions: int64(commit.Additions),
				CommitDeletions: int64(commit.Deletions),
				Commits:         []string{commit.URL},
			}
			repoStats = append(repoStats, repoStat)
		}
	}
	return repoStats
}
