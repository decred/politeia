// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
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
	pr := &database.PullRequest{
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
		`("repo","organization","url","number","author","updated_at","closed_at",` +
		`"merged_at","merged","state","additions","deletions","merged_by") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ` +
		`RETURNING "pullrequests"."url"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
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
			pr.MergedBy).
		WillReturnRows(sqlmock.NewRows([]string{"url"}).AddRow(pr.URL))
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
	pr := &database.PullRequest{
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
		`SET "repo" = $1, "organization" = $2, "number" = $3, ` +
		`"author" = $4, "updated_at" = $5, "closed_at" = $6, ` +
		`"merged_at" = $7, "merged" = $8, "state" = $9, "additions" = $10, ` +
		`"deletions" = $11, "merged_by" = $12 ` +
		`WHERE "pullrequests"."url" = $13`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdatePullRequests)).
		WithArgs(
			pr.Repo,
			pr.Organization,
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
			pr.URL).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdatePullRequest(pr)
	if err != nil {
		t.Errorf("UserUpdate unwanted error: %s", err)
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
		t.Errorf("UserUpdate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
