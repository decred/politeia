package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

type EditProposalCmd struct {
	Args struct {
		Token            string   `positional-arg-name:"token"`
		ProposalMarkdown string   `positional-arg-name:"proposalFilename"`
		Attachments      []string `positional-arg-name:"attachmentsFilenames"`
	} `positional-args:"true" optional:"true"`
	Random bool `long:"random" optional:"true" description:"Generate a random proposal"`
}

func (cmd *EditProposalCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}
	if !cmd.Random && cmd.Args.ProposalMarkdown == "" {
		return fmt.Errorf("You must either provide a markdown file " +
			"or use the --random flag")
	}
	var mdPayload []byte
	var attachments []client.Attachment
	if cmd.Random {
		mdPayload = []byte("This is a name\nThis is a description")
	} else {
		fpath := util.CleanAndExpandPath(cmd.Args.ProposalMarkdown, config.HomeDir)
		f, err := os.Open(fpath)
		if err != nil {
			return fmt.Errorf("Error: %v", err)
		}
		defer f.Close()
		r := bufio.NewReader(f)
		var description string
		var name string
		for i := 0; ; i++ {
			line, err := r.ReadString('\n')
			if i == 0 {
				name = line
			} else {
				description += line
			}
			if err == io.EOF {
				break
			}
		}

		mdPayload = []byte(name + "\n" + description)

		if len(cmd.Args.Attachments) > 0 {
			for _, file := range cmd.Args.Attachments {
				fpath := util.CleanAndExpandPath(file, config.HomeDir)
				f, err := os.Open(fpath)
				if err != nil {
					return err
				}
				defer f.Close()

				fileInfo, _ := f.Stat()
				var size = fileInfo.Size()
				bytes := make([]byte, size)

				// read file into bytes
				buffer := bufio.NewReader(f)
				_, err = buffer.Read(bytes)
				if err != nil {
					return err
				}

				attachments = append(attachments, client.Attachment{
					Filename: filepath.Base(file),
					Payload:  bytes,
				})

			}
		}

	}

	_, err := Ctx.EditProposal(config.UserIdentity, mdPayload, attachments, cmd.Args.Token)
	return err
}
