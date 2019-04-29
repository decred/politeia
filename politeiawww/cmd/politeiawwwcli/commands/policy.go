// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// PolicyCmd gets the server policy information.
type PolicyCmd struct{}

// Execute executes the policy command.
func (cmd *PolicyCmd) Execute(args []string) error {
	pr, err := client.Policy()
	if err != nil {
		return err
	}
	return printJSON(pr)
}

// policyHelpMsg is the output of the help command when 'policy' is specified.
const policyHelpMsg = `policy

Fetch server policy.

Arguments:
None

Response:
{
	"minpasswordlength"          (uint)     Minimum password length
	"minusernamelength"          (uint)     Minimum username length
	"maxusernamelength"          (uint)     Maximum username length 
	"usernamesupportedchars"     ([]string) List of unsupported characters 
	"proposallistpagesize"       (uint)     Maximum proposals per page
	"userlistpagesize"           (uint)     Maximum users per page
	"maximages"                  (uint)     Maximum number of proposal images
	"maximagesize"               (uint)     Maximum image file size (in bytes)
	"maxmds"                     (uint)     Maximum number of markdown files
	"maxmdsize"                  (uint)     Maximum markdown file size (bytes)
	"validmimetypes"             ([]string) List of acceptable MIME types
	"minproposalnamelength"      (uint)     Minimum length of a proposal name
	"maxproposalnamelength"      (uint)     Maximum length of a proposal name
	"proposalnamesupportedchars" ([]string) Regex of a valid proposal name
	"maxcommentlength"           (uint)     Maximum characters in comments
	"backendpublickey"           (string)   Backend public key
	"maxnamelength"              (uint)     Maximum contractor name length (cmswww)
	"minnamelength"              (uint)     Mininum contractor name length (cmswww)
	"maxlocationlength"          (uint)     Maximum contractor location length (cmswww)
	"minlocationlength"          (uint)     Minimum contractor location length (cmswww)
	"invoicecommentchar"         (rune)     Character for comments on invoices (cmswww)
	"invoicefielddelimiterchar"  (rune)     Charactor for invoice csv field seperation (cmswww)
	"invoicelineitemcount"       (uint)     Expected count for line item fields (cmswww)
}`
