package main

import (
	"strconv"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

// ProcessUserNotifications returns all notifications for a given user
func (b *backend) ProcessUserNotifications(user *database.User) (*www.NotificationsReply, error) {
	log.Tracef("ProcessUserNotifications")

	notifications, err := b.db.NotificationsGet(user.Email)
	if err != nil {
		return nil, err
	}
	return &www.NotificationsReply{
		Notifications: convertNotificationsFromDatabase(notifications),
	}, nil
}

// ProcessCheckNotifications set one or multiple notifications as viewed
func (b *backend) ProcessCheckNotifications(user *database.User, ns www.CheckNotifications) (*www.NotificationsReply, error) {
	log.Tracef("ProcessCheckNotifications")

	// Get user notifications
	notifications, err := b.db.NotificationsGet(user.Email)
	if err != nil {
		return nil, err
	}

	// Create a map from notification ids
	ids := make(map[uint64]bool)
	for _, nid := range ns.NotificationIDs {
		ids[nid] = true
	}

	// Update notifications
	notsToUpdate := []database.Notification{}
	for _, n := range notifications {
		if _, ok := ids[n.ID]; ok {
			n.Viewed = true
			notsToUpdate = append(notsToUpdate, n)
		}
	}

	notifications, err = b.db.NotificationsUpdate(notsToUpdate, user.Email)
	if err != nil {
		return nil, err
	}

	return &www.NotificationsReply{
		Notifications: convertNotificationsFromDatabase(notifications),
	}, nil
}

// handleSetNotificationOnSignupPaywallPaid attempts to add a new notification into a user mailbox
// to indicate that the sign up paywall payment has been confirmed
func (b *backend) handleSetNotificationOnSignupPaywallPaid(email string) error {
	return b.db.NotificationNew(database.Notification{
		NotificationType: int(www.NotificationSignupPaywallPaymentConfirmed),
	}, email)
}

// handleSetNotificationOnProposalPaywallPaid attemps to add a new notification into a user mailbox
// to indicate that proposal credits payment has been confirmed
func (b *backend) handleSetNotificationOnProposalPaywallPaid(email string, paywall database.ProposalPaywall) error {
	numCredits := strconv.FormatUint(paywall.TxAmount/paywall.CreditPrice, 10)
	return b.db.NotificationNew(database.Notification{
		NotificationType: int(www.NotificationPropPaywallPaymentConfirmed),
		ContextInfo:      []string{numCredits},
	}, email)
}

// handleSetNotificationOnProposalStartedVoting attempts to add a new notification into a user mailbox
// to indicate that one of his proposals had it's voting started
//
// Must be called WITH the mutext held
func (b *backend) handleSetNotificationOnProposalStartedVoting(pubkey string, token string) error {
	log.Tracef("handleSetNotificationOnProposalStartedVoting")

	// get user
	u, err := b.getUserByPubkey(pubkey)
	if err != nil {
		return err
	}

	return b.db.NotificationNew(database.Notification{
		NotificationType: int(www.NotificationProposalStartedVoting),
		ContextInfo:      []string{token},
	}, u.Email)
}

// handleSetNotificationOnProposalStatusChange attempts to add a new notification into a user mailbox
// to indicate that one of his proposals has been published or censored
//
// Must be called WITH the mutext held
func (b *backend) handleSetNotificationOnProposalStatusChange(pubkey string, token string, st www.PropStatusT) error {
	log.Tracef("handleSetNotificationOnProposalStatusChange")

	// get user
	u, err := b.getUserByPubkey(pubkey)
	if err != nil {
		return err
	}

	switch st {
	case www.PropStatusPublic:
		return b.handleSetNotificationPropPublished(u.Email, token)
	case www.PropStatusCensored:
		return b.handleSetNotificationPropCensored(u.Email, token)
	}

	return nil
}

func (b *backend) handleSetNotificationPropCensored(email string, token string) error {
	log.Tracef("handleSetNotificationOnProposalCensored")
	return b.db.NotificationNew(database.Notification{
		NotificationType: int(www.NotificationProposalCensored),
		ContextInfo:      []string{token},
	}, email)
}

func (b *backend) handleSetNotificationPropPublished(email string, token string) error {
	log.Tracef("handleSetNotificationOnProposalPublished")
	return b.db.NotificationNew(database.Notification{
		NotificationType: int(www.NotificationProposalPublished),
		ContextInfo:      []string{token},
	}, email)
}
