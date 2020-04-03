// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"
	"strings"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/google/uuid"
)

// CMSManageUserCmd allows an administrator to update Domain, ContractorType
// and SupervisorID of a given user.
type CMSManageUserCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" required:"true"`
	} `positional-args:"true" optional:"true"`
	Domain            string `long:"domain" optional:"true"`
	ContractorType    string `long:"contractortype" optional:"true"`
	SupervisorUserIDs string `long:"supervisoruserids" optional:"true"`
	ProposalsOwned    string `long:"proposalsowned" optional:"true"`
}

// Execute executes the cms manage user command.
func (cmd *CMSManageUserCmd) Execute(args []string) error {
	domains := map[string]cms.DomainTypeT{
		"developer":     cms.DomainTypeDeveloper,
		"marketing":     cms.DomainTypeMarketing,
		"research":      cms.DomainTypeResearch,
		"design":        cms.DomainTypeDesign,
		"documentation": cms.DomainTypeDocumentation,
	}
	contractorTypes := map[string]cms.ContractorTypeT{
		"direct":     cms.ContractorTypeDirect,
		"supervisor": cms.ContractorTypeSupervisor,
		"contractor": cms.ContractorTypeSubContractor,
		"nominee":    cms.ContractorTypeNominee,
		"revoked":    cms.ContractorTypeRevoked,
	}

	// Validate user ID
	_, err := uuid.Parse(cmd.Args.UserID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	// Validate domain. The domain can be either the numeric code
	// or the human readable equivalent.
	var domain cms.DomainTypeT
	if cmd.Domain != "" {
		d, err := strconv.ParseUint(cmd.Domain, 10, 32)
		if err == nil {
			// Numeric code found
			domain = cms.DomainTypeT(d)
		} else if d, ok := domains[cmd.Domain]; ok {
			// Human readable domain found
			domain = d
		} else {
			// Invalid domain
			return fmt.Errorf("invalid domain; use the command " +
				"'cmswww help manageuser' for list of valid domains")
		}
	}

	// Validate contractor type. The contractor type can be either
	// a numeric code or the human readable equivalent.
	var contractorType cms.ContractorTypeT
	if cmd.ContractorType != "" {
		ct, err := strconv.ParseUint(cmd.ContractorType, 10, 32)
		if err == nil {
			// Numeric code found
			contractorType = cms.ContractorTypeT(ct)
		} else if ct, ok := contractorTypes[cmd.ContractorType]; ok {
			// Human readable contractor type found
			contractorType = ct
		} else {
			// Invalid contrator type
			return fmt.Errorf("invalid contractor type; use the command " +
				"'cmswww help manageuser' for list of valid contractor types")
		}
	}

	// Validate supervisor user IDs
	supervisorIDs := make([]string, 0, 16)
	if cmd.SupervisorUserIDs != "" {
		supervisorIDs = strings.Split(cmd.SupervisorUserIDs, ",")
		for _, v := range supervisorIDs {
			_, err := uuid.Parse(v)
			if err != nil {
				return fmt.Errorf("invalid supervisor ID '%v': %v", v, err)
			}
		}
	}

	// Validate supervisor user IDs
	proposalsOwned := make([]string, 0, 16)
	if cmd.ProposalsOwned != "" {
		proposalsOwned = strings.Split(cmd.ProposalsOwned, ",")
	}

	// Send request
	mu := cms.CMSManageUser{
		UserID:            cmd.Args.UserID,
		Domain:            domain,
		ContractorType:    contractorType,
		SupervisorUserIDs: supervisorIDs,
		ProposalsOwned:    proposalsOwned,
	}
	err = shared.PrintJSON(mu)
	if err != nil {
		return err
	}
	mur, err := client.CMSManageUser(mu)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(mur)
	if err != nil {
		return err
	}

	return nil
}

const cmsManageUserHelpMsg = `cmsmanageuser [flags] "userid"

Update the Domain, ContractorType and SupervisorID of the specified user. This
command requires admin privileges.

Numeric codes or their human readable equivalents can be used to specify the
domain and contractory type. See below for the available options.

Arguments:
1. userid               (string, required)     ID of the user to manage

Flags:
  --domain              (string, optional)  Domain of the contractor
  --contractortype      (string, optional)  Contractor Type
  --supervisoruserids   (string, optional)  Supervisor user IDs (comma separated)
  --proposalsowned      (string, optional)  Proposals owned (comma separated)

Domain types:
1. developer
2. marketing
4. research
5. design
6. documentation

Contractor types:
1. direct
2. supervisor
3. subcontractor
4. nominee
5. revoked

Request:
{
  "userid": "c1261442-dc61-4861-9d6c-f104fd0b076b",
  "domain": 1,
  "contractortype": 1,
  "supervisoruserids": [
    "f43a040c-585c-4431-a9dd-6dbdde885bb5",
    "914de514-f861-41e3-8fcb-e3ebbb26a333"
  ]
}

Response:
{}`
