package main

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/go-test/deep"
	"github.com/google/uuid"
)

func TestProcessUserCodeStats(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	requestedUser := newCMSUser(t, p, false, true, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)

	noGithubNameSet := newCMSUser(t, p, false, false, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	//sameDomainRequesting := newCMSUser(t, p, cms.DomainTypeDeveloper,
	//	cms.ContractorTypeDirect)
	differentDomain := newCMSUser(t, p, false, true, cms.DomainTypeMarketing,
		cms.ContractorTypeDirect)

	admin := newCMSUser(t, p, true, true, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)

	nonCMSUser, _ := newUser(t, p, true, false)

	var tests = []struct {
		name       string
		params     cms.UserCodeStats
		wantError  error
		requesting *user.User
		wantReply  *cms.UserCodeStatsReply
	}{
		{
			"error invalid dates end before start",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 872842440,
				EndTime:   872841440,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
		{
			"error invalid dates beyond 6 month window",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 872842440,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
		{
			"error can't find requested user id",
			cms.UserCodeStats{
				UserID:    uuid.New().String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
			&admin.User,
			nil,
		},
		{
			"error can't find requesting cms user",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
			nonCMSUser,
			nil,
		},
		{
			"empty reply different domain non-admin",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			nil,
			&differentDomain.User,
			&cms.UserCodeStatsReply{},
		},
		{
			"error can't find requesting cms user",
			cms.UserCodeStats{
				UserID:    noGithubNameSet.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusMissingCodeStatsUsername,
			},
			&admin.User,
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processUserCodeStats(v.params, v.requesting)
			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}

			if err != nil {
				return
			}

			diff := deep.Equal(reply, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}
