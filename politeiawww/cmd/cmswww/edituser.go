// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// EditUserCmd allows a user to edit their own contractor information, such as
// GithubName, MatrixName, Contractor Name, Location and Contact.
type EditUserCmd struct {
	GitHubName         string `long:"githubname" optional:"true" description:"Github handle"`
	MatrixName         string `long:"matrixname" optional:"true" description:"Matrix name"`
	ContractorName     string `long:"contractorname" optional:"true" description:"Identifying IRL name"`
	ContractorLocation string `long:"contractorlocation" optional:"true" description:"IRL location (country or continent)"`
	ContractorContact  string `long:"contact" optional:"true" description:"Contact information"`
}

// Execute executes the cms edit user information command.
func (cmd *EditUserCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	uir, err := client.CMSUserDetails(lr.UserID)
	if err != nil {
		return err
	}

	userInfo := cms.User{}
	if uir != nil {
		userInfo = uir.User
	}
	reader := bufio.NewReader(os.Stdin)
	if cmd.MatrixName != "" || cmd.GitHubName != "" ||
		cmd.ContractorName != "" || cmd.ContractorLocation != "" ||
		cmd.ContractorContact != "" {
		if cmd.MatrixName == "" {
			str := fmt.Sprintf(
				"Your current MatrixName setting is: \"%v\" Update?",
				userInfo.MatrixName)
			update, err := promptListBool(reader, str, "no")
			if err != nil {
				return err
			}
			if update {
				for {
					fmt.Printf("Please enter your Matrix contact name:  ")
					cmd.MatrixName, _ = reader.ReadString('\n')
					cmd.MatrixName = strings.TrimSpace(cmd.MatrixName)
					str := fmt.Sprintf(
						"Your current Matrix name setting is: \"%v\" Keep this?",
						cmd.MatrixName)
					update, err := promptListBool(reader, str, "yes")
					if err != nil {
						return err
					}
					if update {
						userInfo.MatrixName = cmd.MatrixName
						break
					}
				}
			}
		}
		if cmd.GitHubName == "" {
			str := fmt.Sprintf(
				"Your current GitHubName setting is: \"%v\" Update?",
				userInfo.GitHubName)
			update, err := promptListBool(reader, str, "no")
			if err != nil {
				return err
			}
			if update {
				for {
					fmt.Printf("Please enter your GitHubName contact name:  ")
					cmd.GitHubName, _ = reader.ReadString('\n')
					cmd.GitHubName = strings.TrimSpace(cmd.GitHubName)
					str := fmt.Sprintf(
						"Your current GitHubName name setting is: \"%v\" Keep this?",
						cmd.GitHubName)
					update, err := promptListBool(reader, str, "yes")
					if err != nil {
						return err
					}
					if update {
						userInfo.GitHubName = cmd.GitHubName
						break
					}
				}
			}
		}
		if cmd.ContractorName == "" {
			str := fmt.Sprintf(
				"Your current Contractor Name setting is: \"%v\" Update?",
				userInfo.ContractorName)
			update, err := promptListBool(reader, str, "no")
			if err != nil {
				return err
			}
			if update {
				for {
					fmt.Printf("Please enter your IRL contractor name:  ")
					cmd.ContractorName, _ = reader.ReadString('\n')
					cmd.ContractorName = strings.TrimSpace(cmd.ContractorName)
					str := fmt.Sprintf(
						"Your current Contractor Name setting is: \"%v\" Keep this?",
						cmd.ContractorName)
					update, err := promptListBool(reader, str, "yes")
					if err != nil {
						return err
					}
					if update {
						userInfo.ContractorName = cmd.ContractorName
						break
					}
				}
			}
		}
		if cmd.ContractorLocation == "" {
			str := fmt.Sprintf("Your current Contractor Location setting is: \"%v\" Update?",
				userInfo.ContractorLocation)
			update, err := promptListBool(reader, str, "no")
			if err != nil {
				return err
			}
			if update {
				for {
					fmt.Printf("Please enter your IRL contractor location:  ")
					cmd.ContractorLocation, _ = reader.ReadString('\n')
					cmd.ContractorLocation = strings.TrimSpace(cmd.ContractorLocation)
					str := fmt.Sprintf(
						"Your current Contractor location setting is: \"%v\" Keep this?",
						cmd.ContractorLocation)
					update, err := promptListBool(reader, str, "yes")
					if err != nil {
						return err
					}
					if update {
						userInfo.ContractorLocation = cmd.ContractorLocation
						break
					}
				}
			}
		}
		if cmd.ContractorContact == "" {
			str := fmt.Sprintf("Your current Contractor Contact setting is: \"%v\" Update?",
				userInfo.ContractorContact)
			update, err := promptListBool(reader, str, "no")
			if err != nil {
				return err
			}
			if update {
				for {
					fmt.Printf("Please enter your Contractor contact information:  ")
					cmd.ContractorContact, _ = reader.ReadString('\n')
					cmd.ContractorContact = strings.TrimSpace(cmd.ContractorContact)
					str := fmt.Sprintf("Your current Contractor contact setting is: \"%v\" Keep this?",
						cmd.ContractorContact)
					update, err := promptListBool(reader, str, "yes")
					if err != nil {
						return err
					}
					if update {
						userInfo.ContractorContact = cmd.ContractorContact
						break
					}
				}
			}
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your request.")
		reader.ReadString('\n')
	}
	userInfo.MatrixName = cmd.MatrixName
	userInfo.GitHubName = cmd.GitHubName
	userInfo.ContractorName = cmd.ContractorName
	userInfo.ContractorLocation = cmd.ContractorLocation
	userInfo.ContractorContact = cmd.ContractorContact

	updateInfo := cms.EditUser{
		ContractorName:     userInfo.ContractorName,
		ContractorLocation: userInfo.ContractorLocation,
		ContractorContact:  userInfo.ContractorContact,
		MatrixName:         userInfo.MatrixName,
		GitHubName:         userInfo.GitHubName,
	}

	ecur, err := client.CMSEditUser(updateInfo)
	if err != nil {
		return err
	}

	// Print update user information reply. (should be empty)
	return shared.PrintJSON(ecur)
}
