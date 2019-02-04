package main

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/pmezard/go-difflib/difflib"
)

// diffString finds the diff between two structs and returns a string
// representation of the diff.
func diffString(a, b interface{}) (string, error) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(spew.Sdump(a)),
		B:        difflib.SplitLines(spew.Sdump(b)),
		FromFile: "Original",
		ToFile:   "Current",
		Context:  0,
	}
	return difflib.GetUnifiedDiffString(diff)
}

// createNewUser creates a new user in the backend database using randomly
// generated user credentials then returns the NewUser object and the full
// identity for the user.
func createNewUser(b *backend) (*v1.NewUser, *identity.FullIdentity, error) {
	id, err := identity.New()
	if err != nil {
		return nil, nil, err
	}

	r, err := util.Random(int(v1.PolicyMinPasswordLength))
	if err != nil {
		return nil, nil, err
	}

	nu := v1.NewUser{
		Email:     hex.EncodeToString(r) + "@example.com",
		Username:  hex.EncodeToString(r),
		Password:  hex.EncodeToString(r),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	_, err = b.ProcessNewUser(nu)
	if err != nil {
		return nil, nil, err
	}

	return &nu, id, nil
}

func TestProcessUserDetails(t *testing.T) {
	b := createBackend(t)
	defer b.db.Close()

	// Create a user and get the user object from the db. This
	// is the UUID that we'll use to test the UserDetails route.
	nu, _, err := createNewUser(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	dbUser, err := b.db.UserGet(nu.Email)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// UserDetails will either return the full user details or only
	// the public user details depending on who is requesting the
	// data. Full user details includes private data such as email
	// address and payment information.
	user := convertWWWUserFromDatabaseUser(dbUser)
	publicUser := filterUserPublicFields(user)

	// There is no need to test an invalid UUID with ProcessUserDetails
	// since the UUID is a route param and an invalid UUID will result
	// in a 404.

	// Test a valid UUID that does not belong to a user.
	var ud v1.UserDetails
	ud.UserID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	_, err = b.ProcessUserDetails(&ud, false, false)
	if err.(v1.UserError).ErrorCode != v1.ErrorStatusUserNotFound {
		t.Errorf("ProcessUserDetails error got %v, want %v",
			err, v1.ErrorStatusUserNotFound)
	}

	// Use the test user's UUID for the remaining tests.
	ud.UserID = user.ID

	// Create test cases for requesting user details with
	// various privileges.
	var tests = []struct {
		userDetails   v1.UserDetails
		isCurrentUser bool
		isAdmin       bool
		want          v1.User
	}{
		// Publicly available user details.
		{ud, false, false, publicUser},
		// Admin requesting user details.
		{ud, false, true, user},
		// User requesting their own user details.
		{ud, true, false, user},
		// Admin requesting their own user details.
		{ud, true, true, user},
	}

	// Run test cases.
	for _, test := range tests {
		udr, err := b.ProcessUserDetails(&test.userDetails,
			test.isCurrentUser, test.isAdmin)
		if err != nil {
			t.Errorf("ProcessUserDetails error got %v, want %v",
				err, nil)
		}

		// Ensure the correct user object was returned.
		if !reflect.DeepEqual(udr.User, test.want) {
			// Find diff between got and want.
			diff, err := diffString(udr.User, test.want)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Errorf("ProcessUserDetails(ud, %t, %t) = unexpected user object\n%v",
				test.isCurrentUser, test.isAdmin, diff)
		}
	}
}

func TestProcessEditUser(t *testing.T) {
	b := createBackend(t)
	defer b.db.Close()

	// Create a user and get the user object from the db. This
	// is the user we'll be editing.
	nu, _, err := createNewUser(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	user, err := b.db.UserGet(nu.Email)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Create test cases for the different ways a user can
	// update their email notifications.
	tests := []struct {
		notification uint64
		want         []v1.EmailNotificationT
	}{
		// Allow a single notification setting to be set.
		{1, []v1.EmailNotificationT{
			v1.NotificationEmailMyProposalStatusChange,
		}},

		// Allow multiple notifications settings to be set.
		{7, []v1.EmailNotificationT{
			v1.NotificationEmailMyProposalStatusChange,
			v1.NotificationEmailMyProposalVoteStarted,
			v1.NotificationEmailRegularProposalVetted,
		}},

		// Allow invalid notification settings to be set.
		{0, []v1.EmailNotificationT{}},
		{1048576, []v1.EmailNotificationT{}},
	}

	// Run test cases.
	for _, test := range tests {
		_, err := b.ProcessEditUser(&v1.EditUser{
			EmailNotifications: &test.notification,
		}, user)
		if err != nil {
			t.Errorf("ProcessEditUser error got %v, want %v",
				err, nil)
		}

		// Ensure database was updated with the correct notification
		// settings.
		u, err := b.db.UserGet(nu.Email)
		if err != nil {
			t.Fatalf("%v", err)
		}

		var wantBits uint64
		for _, notification := range test.want {
			wantBits |= uint64(notification)
		}

		// Apply a mask so that we ignore invalid bits. The mask value
		// represents all possible notification settings.
		var mask uint64 = 0x1FF
		gotBits := u.EmailNotifications & mask
		if !(wantBits|gotBits == wantBits) {
			t.Errorf("EditUser{ EmailNotifications: %v } got %v, want %v",
				test.notification, gotBits, wantBits)
		}
	}
}
