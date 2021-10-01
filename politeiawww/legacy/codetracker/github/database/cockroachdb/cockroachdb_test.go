// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/legacy/codetracker/github/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func setupTestDB(t *testing.T) (*cockroachdb, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error %s while creating stub db conn", err)
	}

	gdb, err := gorm.Open("postgres", db)
	if err != nil {
		t.Fatalf("error %s while opening db with gorm", err)
	}

	c := &cockroachdb{
		recordsdb: gdb,
	}

	return c, mock, func() {
		db.Close()
	}
}

// Tests
func TestNewPullRequests(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	id := "https://github.com/decred/github/pull/1" +
		strconv.Itoa(int(now.Unix()))
	pr := &database.PullRequest{
		ID:           id,
		Repo:         "github",
		Organization: "decred",
		URL:          "https://github.com/decred/github/pull/1",
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}

	// Queries
	sqlInsertPullRequests := `INSERT INTO "pullrequests" ` +
		`("id","repo","organization","url","number","author","updated_at",` +
		`"closed_at","merged_at","merged","state","additions","deletions",` +
		`"merged_by") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ` +
		`RETURNING "pullrequests"."id"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
		WithArgs(
			pr.ID,
			pr.Repo,
			pr.Organization,
			pr.URL,
			pr.Number,
			pr.User,
			pr.UpdatedAt,
			pr.ClosedAt,
			pr.MergedAt,
			pr.Merged,
			pr.State,
			pr.Additions,
			pr.Deletions,
			pr.MergedBy).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(pr.ID))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewPullRequest(pr)
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

func TestUpdatePullRequests(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	id := "https://github.com/decred/github/pull/1" +
		strconv.Itoa(int(now.Unix()))
	pr := &database.PullRequest{
		ID:           id,
		Repo:         "github",
		Organization: "decred",
		URL:          "https://github.com/decred/github/pull/1",
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}
	// Arguments
	sqlUpdatePullRequests := `UPDATE "pullrequests" ` +
		`SET "repo" = $1, "organization" = $2, "url" = $3, "number" = $4, ` +
		`"author" = $5, "updated_at" = $6, "closed_at" = $7, ` +
		`"merged_at" = $8, "merged" = $9, "state" = $10, "additions" = $11, ` +
		`"deletions" = $12, "merged_by" = $13 ` +
		`WHERE "pullrequests"."id" = $14`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdatePullRequests)).
		WithArgs(
			pr.Repo,
			pr.Organization,
			pr.URL,
			pr.Number,
			pr.User,
			pr.UpdatedAt,
			pr.ClosedAt,
			pr.MergedAt,
			pr.Merged,
			pr.State,
			pr.Additions,
			pr.Deletions,
			pr.MergedBy,
			pr.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdatePullRequest(pr)
	if err != nil {
		t.Errorf("UpdatePullRequest unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestNewPullRequestsReview(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	review := &database.PullRequestReview{
		PullRequestURL: "https://github.com/decred/github/pull/1",
		Author:         "stakey",
		State:          "APPROVED",
		SubmittedAt:    now.Unix(),
		Repo:           "github",
		Number:         1,
		ID:             4934324,
	}

	// Queries
	sqlInsertPullRequests := `INSERT INTO "reviews" ` +
		`("pull_request_url","id","author","state","submitted_at",` +
		`"commit_id","repo","number") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ` +
		`RETURNING "reviews"."id"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
		WithArgs(
			review.PullRequestURL,
			review.ID,
			review.Author,
			review.State,
			review.SubmittedAt,
			sqlmock.AnyArg(),
			review.Repo,
			review.Number,
		).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(review.ID))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewPullRequestReview(review)
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

func TestUpdatePullRequestsReview(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	review := &database.PullRequestReview{
		PullRequestURL: "https://github.com/decred/github/pull/1",
		Author:         "stakey",
		State:          "APPROVED",
		SubmittedAt:    now.Unix(),
		Repo:           "github",
		Number:         1,
		ID:             4934324,
	}
	// Queries
	sqlUpdatePullRequests := `UPDATE "reviews" ` +
		`SET "pull_request_url" = $1, "author" = $2, "state" = $3, ` +
		`"submitted_at" = $4, "commit_id" = $5, "repo" = $6, "number" = $7 ` +
		`WHERE "reviews"."id" = $8`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdatePullRequests)).
		WithArgs(
			review.PullRequestURL,
			review.Author,
			review.State,
			review.SubmittedAt,
			sqlmock.AnyArg(),
			review.Repo,
			review.Number,
			review.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdatePullRequestReview(review)
	if err != nil {
		t.Errorf("UpdatePullRequestReview unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestPullRequestByID(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	url := "https://github.com/decred/pr/pull/1"

	id := url +
		strconv.Itoa(int(now.Unix()))
	idNotFound := url + "123456"
	pr := &database.PullRequest{
		ID:           id,
		Repo:         "github",
		Organization: "decred",
		URL:          url,
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		pr.ID,
		pr.Repo,
		pr.Organization,
		pr.URL,
		pr.Number,
		pr.User,
		pr.UpdatedAt,
		pr.ClosedAt,
		pr.MergedAt,
		pr.Merged,
		pr.State,
		pr.Additions,
		pr.Deletions,
		pr.MergedBy,
	)

	// Query
	sql := `SELECT * FROM "pullrequests" WHERE "pullrequests"."id" = $1`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(id).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.PullRequestByID(id)
	if err != nil {
		t.Errorf("PullRequestByURL unwanted error: %s", err)
	}

	expectedError := database.ErrNoPullRequestFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(idNotFound).
		WillReturnError(expectedError)

	foundPr, err := cdb.PullRequestByID(idNotFound)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if foundPr != nil {
		t.Errorf("expecting nil pr to be returned, but got non-nil pr")
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestMergedPullRequestsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	prURLFirst := "https://github.com/decred/github/pull/1"
	prURLSecond := "https://github.com/decred/github/pull/2"
	prURLThird := "https://github.com/decred/github/pull/3"

	prFirst := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLFirst,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    11,
		Deletions:    11,
		MergedBy:     "davec",
	}

	prSecond := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLSecond,
		Number:       2,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    22,
		Deletions:    22,
		MergedBy:     "davec",
	}

	prThird := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLThird,
		Number:       3,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    33,
		Deletions:    33,
		MergedBy:     "davec",
	}

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		prFirst.Repo,
		prFirst.Organization,
		prFirst.URL,
		prFirst.Number,
		prFirst.User,
		prFirst.UpdatedAt,
		prFirst.ClosedAt,
		prFirst.MergedAt,
		prFirst.Merged,
		prFirst.State,
		prFirst.Additions,
		prFirst.Deletions,
		prFirst.MergedBy,
	).AddRow(
		prSecond.Repo,
		prSecond.Organization,
		prSecond.URL,
		prSecond.Number,
		prSecond.User,
		prSecond.UpdatedAt,
		prSecond.ClosedAt,
		prSecond.MergedAt,
		prSecond.Merged,
		prSecond.State,
		prSecond.Additions,
		prSecond.Deletions,
		prSecond.MergedBy,
	).AddRow(
		prThird.Repo,
		prThird.Organization,
		prThird.URL,
		prThird.Number,
		prThird.User,
		prThird.UpdatedAt,
		prThird.ClosedAt,
		prThird.MergedAt,
		prThird.Merged,
		prThird.State,
		prThird.Additions,
		prThird.Deletions,
		prThird.MergedBy,
	)

	bothRangeStart := now.Add(-2 * time.Hour).Unix()
	bothRangeEnd := now.Add(time.Minute).Unix()

	// Query
	sql := `
	SELECT * ` +
		`FROM "pullrequests" ` +
		`WHERE (author = $1 AND merged_at BETWEEN $2 AND $3)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(prFirst.User, bothRangeStart, bothRangeEnd).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.MergedPullRequestsByUserDates(prFirst.User, bothRangeStart,
		bothRangeEnd)
	if err != nil {
		t.Errorf("MergedPullRequestsByUserDates unwanted error: %s", err)
	}
	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUpdatedPullRequestsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	prURLFirst := "https://github.com/decred/github/pull/1"
	prURLSecond := "https://github.com/decred/github/pull/2"
	prURLThird := "https://github.com/decred/github/pull/3"

	prFirst := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLFirst,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       false,
		State:        "UPDATED",
		Additions:    11,
		Deletions:    11,
		MergedBy:     "davec",
	}

	prSecond := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLSecond,
		Number:       2,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       false,
		State:        "UPDATED",
		Additions:    22,
		Deletions:    22,
		MergedBy:     "davec",
	}

	prThird := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLThird,
		Number:       3,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       false,
		State:        "UPDATED",
		Additions:    33,
		Deletions:    33,
		MergedBy:     "davec",
	}

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		prFirst.Repo,
		prFirst.Organization,
		prFirst.URL,
		prFirst.Number,
		prFirst.User,
		prFirst.UpdatedAt,
		prFirst.ClosedAt,
		prFirst.MergedAt,
		prFirst.Merged,
		prFirst.State,
		prFirst.Additions,
		prFirst.Deletions,
		prFirst.MergedBy,
	).AddRow(
		prSecond.Repo,
		prSecond.Organization,
		prSecond.URL,
		prSecond.Number,
		prSecond.User,
		prSecond.UpdatedAt,
		prSecond.ClosedAt,
		prSecond.MergedAt,
		prSecond.Merged,
		prSecond.State,
		prSecond.Additions,
		prSecond.Deletions,
		prSecond.MergedBy,
	).AddRow(
		prThird.Repo,
		prThird.Organization,
		prThird.URL,
		prThird.Number,
		prThird.User,
		prThird.UpdatedAt,
		prThird.ClosedAt,
		prThird.MergedAt,
		prThird.Merged,
		prThird.State,
		prThird.Additions,
		prThird.Deletions,
		prThird.MergedBy,
	)

	bothRangeStart := now.Add(-2 * time.Hour).Unix()
	bothRangeEnd := now.Add(time.Minute).Unix()

	// Query
	sql := `
	SELECT * FROM pullrequests 
	WHERE author = $1 AND updated_at IN 
	(SELECT 
		MAX(updated_at) 
		FROM pullrequests 
		WHERE updated_at BETWEEN $2 AND $3 
		GROUP BY url
	)
	`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(prFirst.User, bothRangeStart, bothRangeEnd).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.UpdatedPullRequestsByUserDates(prFirst.User, bothRangeStart,
		bothRangeEnd)
	if err != nil {
		t.Errorf("UpdatedPullRequestsByUserDates unwanted error: %s", err)
	}
	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
func TestPullRequestsByURL(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	prURLFirst := "https://github.com/decred/github/pull/1"
	prURLSecond := "https://github.com/decred/github/pull/2"
	prURLThird := "https://github.com/decred/github/pull/3"

	prFirst := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLFirst,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    11,
		Deletions:    11,
		MergedBy:     "davec",
	}

	prSecond := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLSecond,
		Number:       2,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    22,
		Deletions:    22,
		MergedBy:     "davec",
	}

	prThird := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLThird,
		Number:       3,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    33,
		Deletions:    33,
		MergedBy:     "davec",
	}

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		prFirst.Repo,
		prFirst.Organization,
		prFirst.URL,
		prFirst.Number,
		prFirst.User,
		prFirst.UpdatedAt,
		prFirst.ClosedAt,
		prFirst.MergedAt,
		prFirst.Merged,
		prFirst.State,
		prFirst.Additions,
		prFirst.Deletions,
		prFirst.MergedBy,
	).AddRow(
		prSecond.Repo,
		prSecond.Organization,
		prSecond.URL,
		prSecond.Number,
		prSecond.User,
		prSecond.UpdatedAt,
		prSecond.ClosedAt,
		prSecond.MergedAt,
		prSecond.Merged,
		prSecond.State,
		prSecond.Additions,
		prSecond.Deletions,
		prSecond.MergedBy,
	).AddRow(
		prThird.Repo,
		prThird.Organization,
		prThird.URL,
		prThird.Number,
		prThird.User,
		prThird.UpdatedAt,
		prThird.ClosedAt,
		prThird.MergedAt,
		prThird.Merged,
		prThird.State,
		prThird.Additions,
		prThird.Deletions,
		prThird.MergedBy,
	)

	// Query
	sql := `
	SELECT * ` +
		`FROM "pullrequests" ` +
		`WHERE (url = $1)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(prFirst.URL).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.PullRequestsByURL(prFirst.URL)
	if err != nil {
		t.Errorf("PullRequestsByURL unwanted error: %s", err)
	}
	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestReviewByID(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	authorStakey := "stakey"

	prURLFirst := "https://github.com/decred/github/pull/1"

	reviewFirst := &database.PullRequestReview{
		ID:             434234234,
		Repo:           "github",
		PullRequestURL: prURLFirst,
		Number:         1,
		Author:         authorStakey,
		SubmittedAt:    now.Unix(),
		State:          "APPROVED",
		Additions:      11,
		Deletions:      11,
		CommitID:       "abcd1234",
	}

	rows := sqlmock.NewRows([]string{
		"pull_request_url",
		"id",
		"author",
		"state",
		"submitted_at",
		"commit_id",
		"repo",
		"number",
	}).AddRow(
		reviewFirst.PullRequestURL,
		reviewFirst.ID,
		reviewFirst.Author,
		reviewFirst.State,
		reviewFirst.SubmittedAt,
		reviewFirst.CommitID,
		reviewFirst.Repo,
		reviewFirst.Number,
	)

	idNotFound := int64(123456)
	// Query
	sql := `SELECT * FROM "reviews" WHERE "reviews"."id" = $1`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(reviewFirst.ID).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.ReviewByID(reviewFirst.ID)
	if err != nil {
		t.Errorf("PullRequestByURL unwanted error: %s", err)
	}

	expectedError := database.ErrNoPullRequestReviewFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(idNotFound).
		WillReturnError(expectedError)

	foundPr, err := cdb.ReviewByID(idNotFound)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if foundPr != nil {
		t.Errorf("expecting nil pr to be returned, but got non-nil pr")
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestReviewsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	authorStakey := "stakey"

	prURLFirst := "https://github.com/decred/github/pull/1"
	prURLSecond := "https://github.com/decred/github/pull/2"

	reviewFirst := &database.PullRequestReview{
		ID:             434234234,
		Repo:           "github",
		PullRequestURL: prURLFirst,
		Number:         1,
		Author:         authorStakey,
		SubmittedAt:    now.Unix(),
		State:          "APPROVED",
		Additions:      11,
		Deletions:      11,
		CommitID:       "abcd1234",
	}

	reviewSecond := &database.PullRequestReview{
		ID:             434234235,
		Repo:           "github",
		PullRequestURL: prURLSecond,
		Number:         2,
		Author:         authorStakey,
		SubmittedAt:    now.Add(-1 * time.Hour).Unix(),
		State:          "APPROVED",
		CommitID:       "abcd1236",
	}

	rows := sqlmock.NewRows([]string{
		"pull_request_url",
		"id",
		"author",
		"state",
		"submitted_at",
		"commit_id",
		"repo",
		"number",
	}).AddRow(
		reviewFirst.PullRequestURL,
		reviewFirst.ID,
		reviewFirst.Author,
		reviewFirst.State,
		reviewFirst.SubmittedAt,
		reviewFirst.CommitID,
		reviewFirst.Repo,
		reviewFirst.Number,
	).AddRow(
		reviewSecond.PullRequestURL,
		reviewSecond.ID,
		reviewSecond.Author,
		reviewSecond.State,
		reviewSecond.SubmittedAt,
		reviewSecond.CommitID,
		reviewSecond.Repo,
		reviewSecond.Number,
	)

	bothRangeStart := now.Add(-2 * time.Hour).Unix()
	bothRangeEnd := now.Add(time.Minute).Unix()

	// Query
	sql := `
    SELECT 
	  reviews.pull_request_url,
	  reviews.id,
	  reviews.author,
	  reviews.state,
	  reviews.submitted_at,
	  reviews.commit_id,
	  reviews.repo,
	  reviews.number,
	  pullrequests.additions,
	  pullrequests.deletions
    FROM reviews
    INNER JOIN pullrequests
	  ON pullrequests.url = reviews.pull_request_url
    WHERE reviews.author = $1 AND reviews.state = $2 AND 
	  reviews.submitted_at BETWEEN $3 AND $4`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(reviewFirst.Author, "APPROVED", bothRangeStart, bothRangeEnd).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.ReviewsByUserDates(reviewFirst.Author, bothRangeStart,
		bothRangeEnd)
	if err != nil {
		t.Errorf("ReviewsByUserDate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestNewCommits(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	sha := "40deb80dea8c560dfc851a6c0fce6f29f8ecb57a"
	url := "https://api.github.com/repos/decred/politeia/commits/40deb80dea8c560dfc851a6c0fce6f29f8ecb57a"
	commit := &database.Commit{
		SHA:          sha,
		URL:          url,
		Organization: "decred",
		Repo:         "politeia",
		Author:       "stakey",
		Committer:    "stakey",
		Date:         now.Unix(),
		Message:      "This is a sweet commit!",
		ParentSHA:    "8575154a09049b042634333ad39c3a710c309105",
		ParentURL:    "https://api.github.com/repos/decred/politeia/commits/8575154a09049b042634333ad39c3a710c309105",
		Additions:    100,
		Deletions:    99,
	}

	// Queries
	sqlInsertPullRequests := `INSERT INTO "commits" ` +
		`("sha","repo","organization","date","author","committer","message",` +
		`"url","parent_sha","parent_url","additions","deletions") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ` +
		`RETURNING "commits"."sha"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
		WithArgs(
			commit.SHA,
			commit.Repo,
			commit.Organization,
			commit.Date,
			commit.Author,
			commit.Committer,
			commit.Message,
			commit.URL,
			commit.ParentSHA,
			commit.ParentURL,
			commit.Additions,
			commit.Deletions,
		).
		WillReturnRows(sqlmock.NewRows([]string{"sha"}).AddRow(commit.SHA))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewCommit(commit)
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

func TestCommitsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()

	commitFirst := &database.Commit{
		SHA:          "5a673974e617fc2a5bc67878d8161c103583d968",
		URL:          "https://api.github.com/repos/decred/politeia/commits/5a673974e617fc2a5bc67878d8161c103583d968",
		Organization: "decred",
		Repo:         "politeia",
		Author:       "stakey",
		Committer:    "stakey",
		Date:         now.Unix(),
		Message:      "This is a sweet commit! Again",
		ParentSHA:    "8575154a09049b042634333ad39c3a710c309105",
		ParentURL:    "https://api.github.com/repos/decred/politeia/commits/8575154a09049b042634333ad39c3a710c309105",
		Additions:    100,
		Deletions:    99,
	}

	commitSecond := &database.Commit{
		SHA:          "8575154a09049b042634333ad39c3a710c309105",
		URL:          "https://api.github.com/repos/decred/politeia/commits/8575154a09049b042634333ad39c3a710c309105",
		Organization: "decred",
		Repo:         "politeia",
		Author:       "stakey",
		Committer:    "stakey",
		Date:         now.Unix(),
		Message:      "This is a sweet commit!",
		ParentSHA:    "883f75a641b969ce0e7313219efcc0c94f30fd01",
		ParentURL:    "https://api.github.com/repos/decred/politeia/commits/883f75a641b969ce0e7313219efcc0c94f30fd01",
		Additions:    100,
		Deletions:    99,
	}

	rows := sqlmock.NewRows([]string{
		"sha",
		"repo",
		"organization",
		"date",
		"author",
		"committer",
		"message",
		"url",
		"parent_sha",
		"parent_url",
		"additions",
		"deletions",
	}).AddRow(
		commitFirst.SHA,
		commitFirst.Repo,
		commitFirst.Organization,
		commitFirst.Date,
		commitFirst.Author,
		commitFirst.Committer,
		commitFirst.Message,
		commitFirst.URL,
		commitFirst.ParentSHA,
		commitFirst.ParentURL,
		commitFirst.Additions,
		commitFirst.Deletions,
	).AddRow(
		commitSecond.SHA,
		commitSecond.Repo,
		commitSecond.Organization,
		commitSecond.Date,
		commitSecond.Author,
		commitSecond.Committer,
		commitSecond.Message,
		commitSecond.URL,
		commitSecond.ParentSHA,
		commitSecond.ParentURL,
		commitSecond.Additions,
		commitSecond.Deletions,
	)

	bothRangeStart := now.Add(-2 * time.Hour).Unix()
	bothRangeEnd := now.Add(time.Minute).Unix()

	// Query
	sql := `
    SELECT *
    FROM "commits"
    WHERE (author = $1 AND date BETWEEN $2 AND $3)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(commitFirst.Author, bothRangeStart, bothRangeEnd).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.CommitsByUserDates(commitFirst.Author, bothRangeStart,
		bothRangeEnd)
	if err != nil {
		t.Errorf("ReviewsByUserDate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestCommitBySHA(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	commitFirst := &database.Commit{
		SHA:          "5a673974e617fc2a5bc67878d8161c103583d968",
		URL:          "https://api.github.com/repos/decred/politeia/commits/5a673974e617fc2a5bc67878d8161c103583d968",
		Organization: "decred",
		Repo:         "politeia",
		Author:       "stakey",
		Committer:    "stakey",
		Date:         now.Unix(),
		Message:      "This is a sweet commit! Again",
		ParentSHA:    "8575154a09049b042634333ad39c3a710c309105",
		ParentURL:    "https://api.github.com/repos/decred/politeia/commits/8575154a09049b042634333ad39c3a710c309105",
		Additions:    100,
		Deletions:    99,
	}

	rows := sqlmock.NewRows([]string{
		"sha",
		"repo",
		"organization",
		"date",
		"author",
		"committer",
		"message",
		"url",
		"parent_sha",
		"parent_url",
		"additions",
		"deletions",
	}).AddRow(
		commitFirst.SHA,
		commitFirst.Repo,
		commitFirst.Organization,
		commitFirst.Date,
		commitFirst.Author,
		commitFirst.Committer,
		commitFirst.Message,
		commitFirst.URL,
		commitFirst.ParentSHA,
		commitFirst.ParentURL,
		commitFirst.Additions,
		commitFirst.Deletions,
	)

	shaNotFound := "8575154a09049b042634333ad39c3a710c309105"

	// Query
	sql := `SELECT * FROM "commits" WHERE "commits"."sha" = $1`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(commitFirst.SHA).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.CommitBySHA(commitFirst.SHA)
	if err != nil {
		t.Errorf("PullRequestByURL unwanted error: %s", err)
	}

	expectedError := database.ErrNoCommitFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(shaNotFound).
		WillReturnError(expectedError)

	foundPr, err := cdb.CommitBySHA(shaNotFound)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if foundPr != nil {
		t.Errorf("expecting nil pr to be returned, but got non-nil pr")
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
