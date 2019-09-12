// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ManageUserCmd allows a user to edit their own information.  This also
// allows administrators to update a user's information (and more importantly,
// domain, contractor type and supervisorid).  Admin's will have to update this
// information for existing users, but after the DCC is put into production
// that information will be populated upon approved issuance.
type ManageUserCmd struct {
	UserID             string `long:"userid" optional:"true" description:"User ID of the user to edit information"`
	Domain             string `long:"domain" optional:"true" description:"Domain type: Developer, Marketing, Design, Documentation, Research, Community"`
	ContractorType     string `long:"contractortype" optional:"true" description:"Contractor type: Direct, Sub, Super"`
	SupervisorUsername string `long:"supervisoruserid" optional:"true" description:"Supervisor Username"`
}

// Execute executes the cms update user information command.
func (cmd *ManageUserCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	var userID string
	// If it's an admin requesting, get the userID from the options or
	// commandline entry.  Otherwise just request with the current user's ID.
	if lr.IsAdmin {
		reader := bufio.NewReader(os.Stdin)
		if cmd.UserID == "" {
			fmt.Print("Enter the id of the user to edit:")
			userID, _ = reader.ReadString('\n')
		} else {
			userID = cmd.UserID
		}
	} else {
		userID = lr.UserID
	}
	uir, err := client.CMSUserDetails(strings.TrimSpace(userID))
	if err != nil {
		return err
	}

	userInfo := cms.User{}
	if uir != nil {
		userInfo = uir.User
	}
	var domainType, contractorType int
	reader := bufio.NewReader(os.Stdin)
	if cmd.Domain == "" && lr.IsAdmin {
		str := fmt.Sprintf("The current Domain setting is: \"%v\" Update?",
			userInfo.Domain)
		update, err := promptListBool(reader, str, "no")
		if err != nil {
			return err
		}
		if update {
			for {
				fmt.Printf("Domain Type: (1) Developer, (2) Marketing, (3) " +
					"Community, (4) Research, (5) Design, (6) Documentation:  ")
				cmd.Domain, _ = reader.ReadString('\n')
				domainType, err = strconv.Atoi(strings.TrimSpace(cmd.Domain))
				if err != nil {
					fmt.Println("Invalid entry, please try again.")
					continue
				}
				if domainType < 1 || domainType > 6 {
					fmt.Println("Invalid domain type entered, please try again.")
					continue
				}
				str := fmt.Sprintf(
					"Your current Domain setting is: \"%v\" Keep this?",
					domainType)
				update, err := promptListBool(reader, str, "yes")
				if err != nil {
					return err
				}
				if update {
					userInfo.Domain = cms.DomainTypeT(domainType)
					break
				}
			}
		}
	} else if cmd.Domain != "" && lr.IsAdmin {
		domainType, err = strconv.Atoi(strings.TrimSpace(cmd.Domain))
		if err != nil {
			return fmt.Errorf("invalid domain attempted, please try again")
		}
		userInfo.Domain = cms.DomainTypeT(domainType)
	}
	if cmd.ContractorType == "" && lr.IsAdmin {
		str := fmt.Sprintf("Your current Contractor Type setting is: \"%v\" Update?",
			userInfo.ContractorType)
		update, err := promptListBool(reader, str, "no")
		if err != nil {
			return err
		}
		if update {
			for {
				fmt.Printf("(1) Direct, (2) Supervisor, (3) Sub contractor:  ")
				cmd.ContractorType, _ = reader.ReadString('\n')
				contractorType, err = strconv.Atoi(strings.TrimSpace(cmd.ContractorType))
				if err != nil {
					fmt.Println("Invalid entry, please try again.")
					continue
				}
				if contractorType < 1 || contractorType > 3 {
					fmt.Println("Invalid contractor type entered, please try again.")
					continue
				}
				str := fmt.Sprintf(
					"Your current Contractor Type setting is: \"%v\" Keep this?",
					contractorType)
				update, err := promptListBool(reader, str, "yes")
				if err != nil {
					return err
				}
				if update {
					userInfo.ContractorType = cms.ContractorTypeT(contractorType)
					break
				}
			}
		}
	} else if cmd.ContractorType != "" && lr.IsAdmin {
		contractorType, err = strconv.Atoi(strings.TrimSpace(cmd.ContractorType))
		if err != nil {
			return fmt.Errorf("invalid contractor type entered, please try again")

		}
		userInfo.ContractorType = cms.ContractorTypeT(contractorType)
	}
	/*
		XXX Need to decide how to handle Supervisor name lookup for CLI.
			if cmd.SupervisorUsername == "" && lr.IsAdmin  {
				str := fmt.Sprintf("Your current Supervisor ID setting is: %v Update?", userInfo.SupervisorUserID)
				update, err := promptListBool(reader, str, "no")
				if err != nil {
					return err
				}
				if update {
					cmd.SupervisorUsername, _ = reader.ReadString('\n')
				}
				userInfo.SupervisorUserID = cmd.SupervisorUsername
			} else if cmd.SupervisorUsername == "" && lr.IsAdmin {
				userInfo.SupervisorUserID = cmd.SupervisorUsername
			}
	*/
	fmt.Print("\nPlease carefully review your information and ensure it's " +
		"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
		"your request.")
	reader.ReadString('\n')

	updateInfo := cms.ManageUser{
		UserID:         lr.UserID,
		Domain:         userInfo.Domain,
		ContractorType: userInfo.ContractorType,
	}

	ecur, err := client.CMSManageUser(updateInfo)
	if err != nil {
		return err
	}

	// Print update user information reply. (should be empty)
	return shared.PrintJSON(ecur)
}

func parseDomain(domain string) (cms.DomainTypeT, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	switch domain {
	case "developer":
		return cms.DomainTypeDeveloper, nil
	case "marketing":
		return cms.DomainTypeMarketing, nil
	case "community":
		return cms.DomainTypeCommunity, nil
	case "documentation":
		return cms.DomainTypeDocumentation, nil
	case "research":
		return cms.DomainTypeResearch, nil
	case "design":
		return cms.DomainTypeDesign, nil
	default:
		return cms.DomainTypeInvalid, fmt.Errorf("invalid domain type")
	}
}

func parseContractorType(contractorType string) (cms.ContractorTypeT, error) {
	contractorType = strings.ToLower(strings.TrimSpace(contractorType))
	switch contractorType {
	case "direct":
		return cms.ContractorTypeDirect, nil
	case "sub":
		return cms.ContractorTypeSubContractor, nil
	case "super":
		return cms.ContractorTypeSupervisor, nil
	default:
		return cms.ContractorTypeInvalid, fmt.Errorf("invalid domain type")
	}
}
