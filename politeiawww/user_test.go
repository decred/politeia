// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

//import (
//	"encoding/hex"
//	"reflect"
//	"strings"
//	"testing"
//
//	"github.com/davecgh/go-spew/spew"
//	"github.com/decred/politeia/politeiad/api/v1/identity"
//	v1 "github.com/decred/politeia/politeiawww/api/v1"
//	www "github.com/decred/politeia/politeiawww/api/v1"
//	"github.com/decred/politeia/politeiawww/database"
//	"github.com/pmezard/go-difflib/difflib"
//)
//
//// diffString finds the diff between two structs and returns a string
//// representation of the diff.
//func diffString(t *testing.T, a, b interface{}) string {
//	t.Helper()
//
//	diff := difflib.UnifiedDiff{
//		A:        difflib.SplitLines(spew.Sdump(a)),
//		B:        difflib.SplitLines(spew.Sdump(b)),
//		FromFile: "Original",
//		ToFile:   "Current",
//		Context:  0,
//	}
//	d, err := difflib.GetUnifiedDiffString(diff)
//	if err != nil {
//		t.Fatalf("%v", err)
//	}
//
//	return d
//}
//
//func TestProcessUserDetails(t *testing.T) {
//	b := createBackend(t)
//	defer b.db.Close()
//
//	// Create a user and get the user object from the db. This
//	// is the UUID that we'll use to test the UserDetails route.
//	nu, _ := createNewUser(t, b)
//	dbUser, err := b.db.UserGet(nu.Email)
//	if err != nil {
//		t.Fatalf("%v", err)
//	}
//
//	// UserDetails will either return the full user details or only
//	// the public user details depending on who is requesting the
//	// data. Full user details includes private data such as email
//	// address and payment information.
//	user := convertWWWUserFromDatabaseUser(dbUser)
//	publicUser := filterUserPublicFields(user)
//
//	// There is no need to test an invalid UUID with ProcessUserDetails
//	// since the UUID is a route param and an invalid UUID will result
//	// in a 404.
//
//	// Test a valid UUID that does not belong to a user.
//	var ud v1.UserDetails
//	ud.UserID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
//	_, err = b.ProcessUserDetails(&ud, false, false)
//	if err.(v1.UserError).ErrorCode != v1.ErrorStatusUserNotFound {
//		t.Errorf("ProcessUserDetails error got %v, want %v",
//			err, v1.ErrorStatusUserNotFound)
//	}
//
//	// Use the test user's UUID for the remaining tests.
//	ud.UserID = user.ID
//
//	// Create test cases for requesting user details with
//	// various privileges.
//	var tests = []struct {
//		userDetails   v1.UserDetails
//		isCurrentUser bool
//		isAdmin       bool
//		want          v1.User
//	}{
//		// Publicy available user details.
//		{ud, false, false, publicUser},
//		// Admin requesting user details.
//		{ud, false, true, user},
//		// User requesting their own user details.
//		{ud, true, false, user},
//		// Admin requesting their own user details.
//		{ud, true, true, user},
//	}
//
//	// Run test cases.
//	for _, test := range tests {
//		udr, err := b.ProcessUserDetails(&test.userDetails,
//			test.isCurrentUser, test.isAdmin)
//		if err != nil {
//			t.Errorf("ProcessUserDetails error got %v, want %v",
//				err, nil)
//		}
//
//		// Ensure the correct user object was returned.
//		if !reflect.DeepEqual(udr.User, test.want) {
//			t.Errorf("ProcessUserDetails(ud, %t, %t) = unexpected user object\n%v",
//				test.isCurrentUser, test.isAdmin, diffString(t, udr.User, test.want))
//		}
//	}
//}
//
//func TestProcessEditUser(t *testing.T) {
//	b := createBackend(t)
//	defer b.db.Close()
//
//	// Create a user and get the user object from the db. This
//	// is the user we'll be editing.
//	nu, _ := createNewUser(t, b)
//	user, err := b.db.UserGet(nu.Email)
//	if err != nil {
//		t.Fatalf("%v", err)
//	}
//
//	// Create test cases for the different ways a user can
//	// update their email notifications.
//	tests := []struct {
//		notification uint64
//		want         []v1.EmailNotificationT
//	}{
//		// Allow a single notification setting to be set.
//		{1, []v1.EmailNotificationT{
//			v1.NotificationEmailMyProposalStatusChange,
//		}},
//
//		// Allow multiple notifications settings to be set.
//		{7, []v1.EmailNotificationT{
//			v1.NotificationEmailMyProposalStatusChange,
//			v1.NotificationEmailMyProposalVoteStarted,
//			v1.NotificationEmailRegularProposalVetted,
//		}},
//
//		// Allow invalid notification settings to be set.
//		{0, []v1.EmailNotificationT{}},
//		{1048576, []v1.EmailNotificationT{}},
//	}
//
//	// Run test cases.
//	for _, test := range tests {
//		_, err := b.ProcessEditUser(&v1.EditUser{
//			EmailNotifications: &test.notification,
//		}, user)
//		if err != nil {
//			t.Errorf("ProcessEditUser error got %v, want %v",
//				err, nil)
//		}
//
//		// Ensure database was updated with the correct notification
//		// settings.
//		u, err := b.db.UserGet(nu.Email)
//		if err != nil {
//			t.Fatalf("%v", err)
//		}
//
//		var wantBits uint64
//		for _, notification := range test.want {
//			wantBits = wantBits | uint64(notification)
//		}
//
//		// Apply a mask so that we ignore invalid bits. The mask value
//		// represents all possible notification settings.
//		var mask uint64 = 0x1FF
//		gotBits := u.EmailNotifications & mask
//		if !(wantBits|gotBits == wantBits) {
//			t.Errorf("EditUser{ EmailNotifications: %v } got %v, want %v",
//				test.notification, gotBits, wantBits)
//		}
//	}
//}
//
//func createUnverifiedUser(t *testing.T, b *backend) (*database.User, *identity.FullIdentity) {
//	nu, id := createNewUserCommandWithIdentity(t)
//	nur, err := b.ProcessNewUser(nu)
//	assertSuccess(t, err)
//	validateVerificationToken(t, nur.VerificationToken)
//
//	user, _ := b.db.UserGet(nu.Email)
//	return user, id
//}
//
//func verifyUser(t *testing.T, b *backend, user *database.User, identity *identity.FullIdentity, token string) {
//	signature := identity.SignMessage([]byte(token))
//	v := www.VerifyNewUser{
//		Email:             strings.ToUpper(user.Email),
//		VerificationToken: token,
//		Signature:         hex.EncodeToString(signature[:]),
//	}
//	_, err := b.ProcessVerifyNewUser(v)
//	assertSuccess(t, err)
//}
//
//// Tests managing a new user by expiring the verification token.
//func TestProcessManageUser(t *testing.T) {
//	b := createBackend(t)
//	nu, _ := createAndVerifyUser(t, b)
//	adminUser, _ := b.db.UserGet(nu.Email)
//	user, identity := createUnverifiedUser(t, b)
//
//	// Expire the new user verification token
//	eu := www.ManageUser{
//		UserID: user.ID.String(),
//		Action: www.UserManageExpireNewUserVerification,
//		Reason: "unit test",
//	}
//	_, err := b.ProcessManageUser(&eu, adminUser)
//	assertSuccess(t, err)
//
//	// Generate a new verification token
//	rv := www.ResendVerification{
//		Email:     user.Email,
//		PublicKey: hex.EncodeToString(identity.Public.Key[:]),
//	}
//	rvr, err := b.ProcessResendVerification(&rv)
//	assertSuccess(t, err)
//	validateVerificationToken(t, rvr.VerificationToken)
//
//	verifyUser(t, b, user, identity, rvr.VerificationToken)
//
//	b.db.Close()
//}
