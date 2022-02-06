// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"time"
)

const (
	// dateAndTimeFormat contains the reference time format that is used
	// to print a human readable date and time.
	//
	// Reference date: "Mon Jan 2 15:04:05 2006"
	dateAndTimeFormat = "2 Jan 2006 3:04:05pm"

	// userInputDateFormat contains the reference time format that is used to
	// parse user input dates.
	//
	// Reference date: "Mon Jan 2 15:04:05 2006"
	userInputDateFormat = "01/02/2006"

	// locationName is the name of the time zone location that is used
	// in the human readable timestamps.
	locationName = "Local"
)

// dateAndTimeFromUnix converts a unix timestamp into a human readable
// timestamp string formatted according to the dateAndTime global variable.
func dateAndTimeFromUnix(unixTime int64) string {
	t := time.Unix(unixTime, 0)
	return t.Format(dateAndTimeFormat)
}

// dateFromUnix coverts a unix timestamp into a human readable timestamp string
// formatted according to the userInputDateFormat global variable.
func dateFromUnix(unixTime int64) string {
	t := time.Unix(unixTime, 0)
	return t.Format(userInputDateFormat)
}

// unixFromDate converts a human readable timestamp string formatted according
// to the userInputDateFormat global variable into a unix timestamp.
func unixFromDate(timestamp string) (int64, error) {
	location, err := time.LoadLocation(locationName)
	if err != nil {
		return 0, err
	}
	t, err := time.ParseInLocation(userInputDateFormat, timestamp, location)
	if err != nil {
		return 0, err
	}

	return t.Unix(), nil
}
