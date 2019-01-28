package commands

// Help message displayed for the command 'politeiawwwcli help policy'
var PolicyCmdHelpMsg = `policy

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
}`

type PolicyCmd struct{}

func (cmd *PolicyCmd) Execute(args []string) error {
	pr, err := c.Policy()
	if err != nil {
		return err
	}
	return Print(pr, cfg.Verbose, cfg.RawJSON)
}
