// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// proposalEditCmd edits an existing proposal.
type proposalEditCmd struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"`
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachmets"`
	} `positional-args:"true" optional:"true"`

	// Unvetted is used to indicate that the state of the requested
	// proposal is unvetted. If this flag is not used it will be
	// assumed that a vetted proposal is being requested.
	Unvetted bool `long:"unvetted" optional:"true"`

	// Random generates random proposal data. An IndexFile and
	// Attachments are not required when using this flag.
	Random bool `long:"random" optional:"true"`

	// The following flags can be used to specify user defined proposal
	// metadata values.
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy int64  `long:"linkby" optional:"true"`

	// RFP is a flag that is intended to make editing an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a specific timestamp using the
	// --linkby flag.
	RFP bool `long:"rfp" optional:"true"`

	// UseMD is a flag that is intended to make editing proposal
	// metadata easier by using exisiting proposal metadata values
	// instead of having to pass in specific values.
	UseMD bool `long:"usemd" optional:"true"`
}

// Execute executes the proposalEditCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *proposalEditCmd) Execute(args []string) error {
	/*
		// Unpack args
		token := c.Args.Token
		indexFile := c.Args.IndexFile
		attachments := c.Args.Attachments

		// Verify args
		switch {
		case !c.Random && indexFile == "":
			return fmt.Errorf("index file not found; you must either " +
				"provide an index.md file or use --random")

		case c.Random && indexFile != "":
			return fmt.Errorf("you cannot provide file arguments and use " +
				"the --random flag at the same time")

		case !c.Random && c.Name == "":
			return fmt.Errorf("you must either provide a proposal name " +
				"using the --name flag or use the --random flag to generate " +
				"a random proposal")

		case c.RFP && c.LinkBy != 0:
			return fmt.Errorf("you cannot use both the --rfp and --linkby " +
				"flags at the same time")
		}

		// Check for user identity. A user identity is required to sign
		// the proposal files.
		if cfg.Identity == nil {
			return shared.ErrUserIdentityNotFound
		}

		// Setup client
		pc, err := pclient.New(cfg.Host, cfg.HTTPSCert, cfg.Cookies, cfg.CSRF)
		if err != nil {
			return err
		}

		// Get the pi policy. It contains the proposal requirements.
		pr, err := pc.PiPolicy()
		if err != nil {
			return err
		}

		// Setup state
		var state string
		switch {
		case c.Unvetted:
			state = rcv1.RecordStateUnvetted
		default:
			state = rcv1.RecordStateVetted
		}

		// Setup index file
		var (
			file  *rcv1.File
			files = make([]rcv1.File, 0, 16)
		)
		if c.Random {
			// Generate random text for the index file
			file, err = createMDFile()
			if err != nil {
				return err
			}
		} else {
			// Read index file from disk
			fp := util.CleanAndExpandPath(indexFile)
			var err error
			payload, err := ioutil.ReadFile(fp)
			if err != nil {
				return fmt.Errorf("ReadFile %v: %v", fp, err)
			}
			file = &rcv1.File{
				Name:    piplugin.FileNameIndexFile,
				MIME:    mime.DetectMimeType(payload),
				Digest:  hex.EncodeToString(util.Digest(payload)),
				Payload: base64.StdEncoding.EncodeToString(payload),
			}
		}
		files = append(files, *file)

		// Setup attachment files
		for _, fn := range attachments {
			fp := util.CleanAndExpandPath(fn)
			payload, err := ioutil.ReadFile(fp)
			if err != nil {
				return fmt.Errorf("ReadFile %v: %v", fp, err)
			}

			files = append(files, rcv1.File{
				Name:    filepath.Base(fn),
				MIME:    mime.DetectMimeType(payload),
				Digest:  hex.EncodeToString(util.Digest(payload)),
				Payload: base64.StdEncoding.EncodeToString(payload),
			})
		}

		// Setup proposal metadata
		switch {
		case c.UseMD:
			// Use the prexisting proposal name

		case c.Random:
			// Create a random proposal name
			r, err := util.Random(int(pr.NameLengthMin))
			if err != nil {
				return err
			}
			c.Name = hex.EncodeToString(r)
		}
		pm := piv1.ProposalMetadata{
			Name: c.Name,
		}
		pmb, err := json.Marshal(pm)
		if err != nil {
			return err
		}
		files = append(files, rcv1.File{
			Name:    piv1.FileNameProposalMetadata,
			MIME:    mime.DetectMimeType(pmb),
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Payload: base64.StdEncoding.EncodeToString(pmb),
		})
	*/

	return nil
}

// proposalEditHelpMsg is the output of the help command.
const proposalEditHelpMsg = `editproposal [flags] "token" "indexfile" "attachments" 

Edit a proposal. This command assumes the proposal is a vetted record. If
the proposal is unvetted, the --unvetted flag must be used. Requires admin
priviledges.

Arguments:
1. token         (string, required) Proposal censorship token
2. indexfile     (string, required) Index file
3. attachments   (string, optional) Attachment files

Flags:
  --unvetted (bool, optional)    Comment on unvetted record.
  --random   (bool, optional)    Generate a random proposal name & files to
                                 submit. If this flag is used then the markdown
                                 file argument is no longer required and any 
                                 provided files will be ignored.
  --usemd    (bool, optional)    Use the existing proposal metadata.
  --name     (string, optional)  The name of the proposal.
  --linkto   (string, optional)  Censorship token of an existing public proposal
                                 to link to.
  --linkby   (int64, optional)   UNIX timestamp of RFP deadline.
  --rfp      (bool, optional)    Make the proposal an RFP by inserting a LinkBy
                                 timestamp into the proposal metadata. The LinkBy
                                 timestamp is set to be one month from the
                                 current time. This is intended to be used in
                                 place of --linkby.`
