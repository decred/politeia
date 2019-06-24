// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// CMSEditUserCmd updates a user's information.
type CMSEditUserCmd struct {
	Domain             string `long:"domain" optional:"true" description:"Domain type: Developer, Marketing, Design, Documentation, Research, Community"`
	GitHubName         string `long:"githubname" optional:"true" description:"Github handle"`
	MatrixName         string `long:"matrixname" optional:"true" description:"Matrix name"`
	ContractorType     string `long:"contractortype" optional:"true" description:"Contractor type: Direct, Sub, Super"`
	ContractorName     string `long:"contractorname" optional:"true" description:"Identifying IRL name"`
	ContractorLocation string `long:"contractorlocation" optional:"true" description:"IRL location (country or continent)"`
	ContractorContact  string `long:"contact" optional:"true" description:"Contact information"`
	SupervisorUsername string `long:"supervisoruserid" optional:"true" description:"Supervisor Username"`
}

// Execute executes the cms update user information command.
func (cmd *CMSEditUserCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}
	uir, err := client.CMSUserDetails()
	if err != nil {
		fmt.Println(err)
	}
	userInfo := cms.CMSUser{}
	if uir != nil && uir.User != nil {
		userInfo = *uir.User
	}
	var domainType, contractorType int
	if cmd.Domain == "" || cmd.GitHubName == "" ||
		cmd.MatrixName == "" || cmd.ContractorType == "" ||
		cmd.ContractorName == "" || cmd.ContractorLocation == "" ||
		cmd.ContractorContact == "" || cmd.SupervisorUsername == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Domain == "" {
			str := fmt.Sprintf("Your current Domain setting is: \"%v\" Update?",
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
		}
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
		if cmd.ContractorType == "" {
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
		/*
			XXX Need to decide how to handle Supervisor name lookup for CLI.
				if cmd.SupervisorUsername == "" {
					str := fmt.Sprintf("Your current Supervisor ID setting is: %v Update?", userInfo.SupervisorUserID)
					update, err := promptListBool(reader, str, "no")
					if err != nil {
						return err
					}
					if update {
						cmd.SupervisorUsername, _ = reader.ReadString('\n')
					}
					userInfo.SupervisorUserID = cmd.SupervisorUsername
				}
		*/
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your registration.")
		reader.ReadString('\n')
	}
	userInfoRaw, err := json.Marshal(userInfo)
	if err != nil {
		return fmt.Errorf("execute CMSEditUserCmd: Marshal UserInformation %v",
			err)
	}
	sig := cfg.Identity.SignMessage(userInfoRaw)

	updateInfo := cms.EditUser{
		CMSUser:   userInfo,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	ecur, err := client.CMSEditUser(updateInfo)
	if err != nil {
		return err
	}

	// Print update user information reply. (should be empty)
	return printJSON(ecur)
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
