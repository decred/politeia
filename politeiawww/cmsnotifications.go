// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"time"

	"github.com/thi4go/politeia/politeiawww/user"
)

// Seconds Minutes Hours Days Months DayOfWeek
const emailSchedule = "0 0 12 5 * *" // Check at 12:00 PM on 5th day every month

func (p *politeiawww) checkInvoiceNotifications() {
	log.Infof("Starting cron for invoice email checking")
	// Launch invoice notification cron job
	err := p.cron.AddFunc(emailSchedule, func() {
		log.Infof("Running invoice email notification cron")
		currentMonth := time.Now().Month()
		currentYear := time.Now().Year()
		// Check all CMS users
		err := p.db.AllUsers(func(user *user.User) {
			log.Tracef("Checking user: %v", user.Username)
			if user.Admin {
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
				err = p.emailInvoiceNotifications(user.Email, user.Username)
				if err != nil {
					log.Errorf("Error sending email: %v %v", err, user.Email)
				}
			}
		})
		if err != nil {
			log.Errorf("Error querying for AllUsers: %v", err)
		}
	})
	if err != nil {
		log.Errorf("Error running invoice notification cron: %v", err)
	}
	p.cron.Start()
}
