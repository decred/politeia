// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/legacy/user"
)

const (
	// Seconds Minutes Hours Days Months DayOfWeek
	firstEmailSchedule  = "0 0 12 1 * *" // Check at 12:00 PM on 1st day every month
	secondEmailSchedule = "0 0 12 4 * *" // Check at 12:00 PM on 4th day every month
	thirdEmailSchedule  = "0 0 12 7 * *" // Check at 12:00 PM on 7th day every month

	firstEmailCheck  = 1
	secondEmailCheck = 2
	thirdEmailCheck  = 3
)

func (p *LegacyPoliteiawww) checkInvoiceNotifications() {
	log.Infof("Starting cron for invoice email checking")
	// Launch invoice notification cron job
	err := p.cron.AddFunc(firstEmailSchedule, func() {
		log.Infof("Running first invoice email notification cron")
		p.invoiceNotification(firstEmailCheck)
	})
	if err != nil {
		log.Errorf("Error running first invoice notification cron: %v", err)
	}
	err = p.cron.AddFunc(secondEmailSchedule, func() {
		log.Infof("Running second invoice email notification cron")
		p.invoiceNotification(secondEmailCheck)
	})
	if err != nil {
		log.Errorf("Error running second invoice notification cron: %v", err)
	}
	err = p.cron.AddFunc(thirdEmailSchedule, func() {
		log.Infof("Running third invoice email notification cron")
		p.invoiceNotification(thirdEmailCheck)
	})
	if err != nil {
		log.Errorf("Error running third invoice notification cron: %v", err)
	}
}

func (p *LegacyPoliteiawww) invoiceNotification(emailCheckVersion int) {
	currentMonth := time.Now().Month()
	currentYear := time.Now().Year()
	// Check all CMS users
	err := p.db.AllUsers(func(user *user.User) {
		log.Tracef("Checking user: %v", user.Username)
		if user.Admin {
			return
		}

		cmsUser, err := p.getCMSUserByID(user.ID.String())
		if err != nil {
			log.Errorf("Error retrieving user invoices email: %v %v", err,
				user.Email)
			return
		}

		// Skip if user isn't a direct or supervisor contractor.
		if cmsUser.ContractorType != cms.ContractorTypeDirect &&
			cmsUser.ContractorType != cms.ContractorTypeSupervisor {
			return
		}

		// If HashedPassword not set to anything that means the user has
		// not completed registration.
		if len(user.HashedPassword) == 0 {
			return
		}
		invoiceFound := false
		userInvoices, err := p.cmsDB.InvoicesByUserID(user.ID.String())
		if err != nil {
			log.Errorf("Error retrieving user invoices email: %v %v", err,
				user.Email)
			return
		}
		for _, inv := range userInvoices {
			// Check to see if invoices match last month + current year OR
			// if it's currently January and the user has not submitted an
			// invoice for December of the previous year.
			if (inv.Month == uint(currentMonth-1) &&
				inv.Year == uint(currentYear)) ||
				(currentMonth == 1 && inv.Month == 12 &&
					inv.Year == uint(currentYear-1)) {
				invoiceFound = true
				break
			}
		}
		log.Tracef("Checked user: %v sending email? %v", user.Username,
			!invoiceFound)
		if !invoiceFound {
			switch emailCheckVersion {
			case firstEmailCheck:
				err = p.emailInvoiceNotifications(user.Email, user.Username,
					"Monthly Invoice Reminder",
					invoiceFirstNotificationTmpl)
				if err != nil {
					log.Errorf("Error sending first email: %v %v", err, user.Email)
				}
			case secondEmailCheck:
				err = p.emailInvoiceNotifications(user.Email, user.Username,
					"Awaiting Monthly Invoice",
					invoiceSecondNotificationTmpl)
				if err != nil {
					log.Errorf("Error sending second email: %v %v", err, user.Email)
				}

			case thirdEmailCheck:
				err = p.emailInvoiceNotifications(user.Email, user.Username,
					"Final Invoice Notice",
					invoiceFinalNotificationTmpl)
				if err != nil {
					log.Errorf("Error sending second email: %v %v", err, user.Email)
				}
			}
		}
	})
	if err != nil {
		log.Errorf("Error querying for AllUsers: %v", err)
	}
}
