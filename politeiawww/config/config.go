// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package config

import (
	"crypto/x509"
	"path/filepath"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

const (
	// DefaultConfigFilename is the default configuration file name.
	DefaultConfigFilename = "politeiawww.conf"

	// DefaultDataDirname is the default data directory name. The data
	// directory is located in the application home directory.
	DefaultDataDirname = "data"

	// Currently available modes to run politeia, by default piwww, is
	// used.
	PoliteiaWWWMode = "piwww"
	CMSWWWMode      = "cmswww"
)

var (
	// DefaultHomeDir points to politeiawww's default home directory.
	DefaultHomeDir = dcrutil.AppDataDir("politeiawww", false)

	// DefaultConfigFile points to politeiawww's default config file
	// path.
	DefaultConfigFile = filepath.Join(DefaultHomeDir, DefaultConfigFilename)

	// DefaultDataDir points to politeiawww's default data directory
	// path.
	DefaultDataDir = filepath.Join(DefaultHomeDir, DefaultDataDirname)

	// DefaultHTTPSCertFile contains the file path to the politeiawww
	// https certificate.
	DefaultHTTPSCertFile = filepath.Join(DefaultHomeDir, "https.cert")
)

// Config defines the configuration options for politeiawww.
type Config struct {
	HomeDir         string   `short:"A" long:"appdata" description:"Path to application home directory"`
	ShowVersion     bool     `short:"V" long:"version" description:"Display version information and exit"`
	ConfigFile      string   `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir         string   `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir          string   `long:"logdir" description:"Directory to log output."`
	TestNet         bool     `long:"testnet" description:"Use the test network"`
	SimNet          bool     `long:"simnet" description:"Use the simulation test network"`
	Profile         string   `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	CookieKeyFile   string   `long:"cookiekey" description:"File containing the secret cookies key"`
	DebugLevel      string   `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Listeners       []string `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 4443)"`
	HTTPSCert       string   `long:"httpscert" description:"File containing the https certificate file"`
	HTTPSKey        string   `long:"httpskey" description:"File containing the https certificate key"`
	RPCHost         string   `long:"rpchost" description:"Host for politeiad in this format"`
	RPCCert         string   `long:"rpccert" description:"File containing the https certificate file"`
	RPCIdentityFile string   `long:"rpcidentityfile" description:"Path to file containing the politeiad identity"`
	RPCUser         string   `long:"rpcuser" description:"RPC user name for privileged politeaid commands"`
	RPCPass         string   `long:"rpcpass" description:"RPC password for privileged politeiad commands"`
	FetchIdentity   bool     `long:"fetchidentity" description:"Whether or not politeiawww fetches the identity from politeiad."`
	Interactive     string   `long:"interactive" description:"Set to i-know-this-is-a-bad-idea to turn off interactive mode during --fetchidentity."`
	AdminLogFile    string   `long:"adminlogfile" description:"admin log filename (Default: admin.log)"`
	Mode            string   `long:"mode" description:"Mode www runs as. Supported values: piwww, cmswww"`

	// Webserver settings
	ReqBodySizeLimit   int64 `long:"reqbodysizelimit" description:"Maximum number of bytes allowed for a request body from a http client"`
	WebsocketReadLimit int64 `long:"websocketreadlimit" description:"Maximum number of bytes allowed for a message read from a websocket client"`

	// User database settings
	UserDB           string `long:"userdb" description:"Database choice for the user database"`
	DBHost           string `long:"dbhost" description:"Database ip:port"`
	DBRootCert       string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
	DBCert           string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
	DBKey            string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
	DBPass           string // Provided in env variable "DBPASS"
	EncryptionKey    string `long:"encryptionkey" description:"File containing encryption key used for encrypting user data at rest"`
	OldEncryptionKey string `long:"oldencryptionkey" description:"File containing old encryption key (only set when rotating keys)"`

	// SMTP settings
	MailHost         string `long:"mailhost" description:"Email server address in this format: <host>:<port>"`
	MailUser         string `long:"mailuser" description:"Email server username"`
	MailPass         string `long:"mailpass" description:"Email server password"`
	MailAddress      string `long:"mailaddress" description:"Email address for outgoing email in the format: name <address>"`
	MailCert         string `long:"mailcert" description:"Email server certificate file"`
	MailSkipVerify   bool   `long:"mailskipverify" description:"Skip TLS verification when connecting to the mail server"`
	MailRateLimit    int    `long:"mailratelimit" description:"Limits the amount of emails a user can receive in 24h"`
	WebServerAddress string `long:"webserveraddress" description:"Web server address used to create email links (format: <scheme>://<host>[:<port>])"`

	// XXX These should all be plugin settings
	DcrdataHost              string   `long:"dcrdatahost" description:"Dcrdata ip:port"`
	PaywallAmount            uint64   `long:"paywallamount" description:"Amount of DCR (in atoms) required for a user to register or submit a proposal."`
	PaywallXpub              string   `long:"paywallxpub" description:"Extended public key for deriving paywall addresses."`
	MinConfirmationsRequired uint64   `long:"minconfirmations" description:"Minimum blocks confirmation for accepting paywall as paid. Only works in TestNet."`
	BuildCMSDB               bool     `long:"buildcmsdb" description:"Build the cmsdb from scratch"`
	GithubAPIToken           string   `long:"githubapitoken" description:"API Token used to communicate with github API.  When populated in cmswww mode, github-tracker is enabled."`
	CodeStatRepos            []string `long:"codestatrepos" description:"Org/Repositories to crawl for code statistics"`
	CodeStatOrganization     string   `long:"codestatorg" description:"Organization to crawl for code statistics"`
	CodeStatStart            int64    `long:"codestatstart" description:"Date in which to look back to for code stat crawl (default 6 months back)"`
	CodeStatEnd              int64    `long:"codestatend" description:"Date in which to end look back to for code stat crawl (default today)"`
	CodeStatSkipSync         bool     `long:"codestatskipsync" description:"Skip pull request crawl on startup"`
	VoteDurationMin          uint32   `long:"votedurationmin" description:"Minimum duration of a dcc vote in blocks"`
	VoteDurationMax          uint32   `long:"votedurationmax" description:"Maximum duration of a dcc vote in blocks"`

	Version     string
	Identity    *identity.PublicIdentity
	SystemCerts *x509.CertPool
}
