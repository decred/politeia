// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"regexp"
	"strconv"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func newCdbCMSUser(usr user.User, domain, contractorType int, t *testing.T, cdb *cockroachdb) CMSUser {
	t.Helper()

	u := CMSUser{
		ID:             usr.ID,
		Domain:         domain,
		ContractorType: contractorType,
	}

	return u
}

// Tests
func TestNewCodeStats(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	userID := uuid.New()
	githubName := "github"
	repo := "decred"
	monthAug := 8
	prsAug := []string{"https://github.com/decred/pr/pull/1",
		"https://github.com/decred/pr/pull/2"}
	reviewsAug := []string{"https://github.com/decred/review/pull/1",
		"https://github.com/decred/review/pull/1"}
	mergeAdditionsAug := 100
	mergeDeletionsAug := 99
	reviewAdditionsAug := 200
	reviewDeletionsAug := 199

	monthSept := 9
	prsSept := []string{"https://github.com/decred/pr/pull/3",
		"https://github.com/decred/pr/pull/4"}
	reviewsSept := []string{"https://github.com/decred/review/pull/3",
		"https://github.com/decred/review/pull/4"}
	mergeAdditionsSept := 100
	mergeDeletionsSept := 99
	reviewAdditionsSept := 200
	reviewDeletionsSept := 199

	year := 2020

	augID := userID.String() + githubName + strconv.Itoa(monthAug) +
		strconv.Itoa(year)
	codeStats := make([]user.CodeStats, 0, 2)
	codeStats = append(codeStats, user.CodeStats{
		Repository: repo,
		Month:      monthAug,
		Year:       year,
	})
	septID := userID.String() + githubName + strconv.Itoa(monthSept) +
		strconv.Itoa(year)
	codeStats = append(codeStats, user.CodeStats{
		Repository: repo,
		Month:      monthSept,
		Year:       year,
	})
	nu := &user.NewCMSCodeStats{
		UserCodeStats: codeStats,
	}

	// Queries
	sqlInsertCMSCodeStats := `INSERT INTO "cms_code_stats" ` +
		`("id","git_hub_name","repository","month","year","prs","reviews",` +
		`"merge_additions","merge_deletions","review_additions",` +
		`"review_deletions","created_at","updated_at") VALUES ` +
		`($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ` +
		`RETURNING "cms_code_stats"."id"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertCMSCodeStats)).
		WithArgs(sqlmock.AnyArg(), githubName, monthAug, year, prsAug,
			reviewsAug, mergeAdditionsAug, mergeDeletionsAug, reviewAdditionsAug,
			reviewDeletionsAug, AnyTime{}, AnyTime{}).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(augID))
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertCMSCodeStats)).
		WithArgs(sqlmock.AnyArg(), githubName, monthSept, year, prsSept,
			reviewsSept, mergeAdditionsSept, mergeDeletionsSept,
			reviewAdditionsSept, reviewDeletionsSept, AnyTime{}, AnyTime{}).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(septID))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewCMSCodeStats(nu)
	if err != nil {
		t.Errorf("UserNew unwanted error: %s", err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

/*
func TestUpdateCodeStats(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	index := newPaywallAddressIndex(t, 1)
	usr := user.User{
		Email:    "test@test.com",
		Username: "test",
	}

	// Queries
	sqlSelectIndex := `SELECT * FROM "key_value" WHERE "key_value"."key" = $1`
	sqlInsertUser := `INSERT INTO "users" ` +
		`("id","username","blob","created_at","updated_at") ` +
		`VALUES ($1,$2,$3,$4,$5) ` +
		`RETURNING "users"."id"`
	sqlUpdateIndex := `UPDATE "key_value" SET "value" = $1 ` +
		`WHERE "key_value"."key" = $2`

	// Success Expectations
	mock.ExpectBegin()
	// Select paywall address index
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value"}).
			AddRow(keyPaywallAddressIndex, index))
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{},
			AnyTime{}, AnyTime{}).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(usr.ID))
	// Update paywall address index
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateIndex)).
		WithArgs(sqlmock.AnyArg(), keyPaywallAddressIndex).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UserNew(usr)
	if err != nil {
		t.Errorf("UserNew unwanted error: %s", err)
	}

	// Negative Expectations
	expectedError := user.ErrUserExists
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sqlSelectIndex)).
		WithArgs(keyPaywallAddressIndex).
		WillReturnRows(sqlmock.NewRows([]string{"key", "value"}).
			AddRow(keyPaywallAddressIndex, index))
	// User already exists error
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertUser)).
		WithArgs(sqlmock.AnyArg(), usr.Username, AnyBlob{},
			AnyTime{}, AnyTime{}).
		WillReturnError(expectedError)
	mock.ExpectRollback()

	// Execute method
	err = cdb.UserNew(usr)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	// Make sure we got the expected error
	if err.Error() != fmt.Errorf("create user: %v", expectedError).Error() {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUpdateCodeStats(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	id := uuid.New()
	usr := user.User{
		ID:         id,
		Identities: []user.Identity{},
		Email:      "test@test.com",
		Username:   "test",
	}

	// Query
	sql := `UPDATE "users" ` +
		`SET "username" = $1, "blob" = $2, "updated_at" = $3 ` +
		`WHERE "users"."id" = $4`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username, AnyBlob{}, AnyTime{}, usr.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UserUpdate(usr)
	if err != nil {
		t.Errorf("UserUpdate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestCodeStatsByUserMonthYear(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	usr, blob := newCdbUser(t, cdb)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"username",
		"blob",
		"created_at",
		"updated_at",
	}).AddRow(usr.ID, usr.Username, blob, now, now)

	// Query
	sql := `SELECT * FROM "users" WHERE (username = $1)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(usr.Username).
		WillReturnRows(rows)

	// Execute method
	u, err := cdb.UserGetByUsername(usr.Username)
	if err != nil {
		t.Errorf("UserGetByUsername unwanted error: %s", err)
	}

	// Make sure correct user was fetched
	if u.ID != usr.ID {
		t.Errorf("expecting user of id %s but received %s", usr.ID, u.ID)
	}

	// Negative Expectations
	randomUsername := "random"
	expectedError := user.ErrUserNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomUsername).
		WillReturnError(expectedError)

	// Execute method
	u, err = cdb.UserGetByUsername(randomUsername)
	if err == nil {
		t.Errorf("expecting error %s, but there was none", expectedError)
	}

	// Make sure no user was fetched
	if u != nil {
		t.Errorf("expecting nil user to be returned, but got user %s", u.ID)
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
*/
