// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sampleconfig

// FileContents is a string containing the commented example config for dcrd.
const FileContents = `[Application Options]

; ------------------------------------------------------------------------------
; Data settings
; ------------------------------------------------------------------------------

; The directory to store data such as the logs and journals. The default is 
; ~/.politeiavoter on POSIX OSes, $LOCALAPPDATA/Politeiavoter on Windows,
; ~/Library/Application Support/Politeiavoter on macOS, and 
; $homed/politeiavoter/data on Plan9.  Environment variables are expanded so they
; may be used.  NOTE: Windows environment variables are typically %VARIABLE%, but
; they must be accessed with $VARIABLE here.
; appdata=~/.politeiavoter                            ; Unix
; appdata=$LOCALAPPDATA/Politeiavoter                 ; Windows
; appdata=~/Library/Application Support/Politeiavoter ; macOS

; ------------------------------------------------------------------------------
; Network settings
; ------------------------------------------------------------------------------

; Use testnet.
; testnet=1

; Connect via a SOCKS5 proxy. This is required when trickling votes.
; The SOCKS5 proxy is assumed to be Tor (https://www.torproject.org).
; trickle=1
; proxy=127.0.0.1:9050
; proxyuser=
; proxypass=

; ------------------------------------------------------------------------------
; Wallet
; ------------------------------------------------------------------------------

; Politeiavoter requires wallet access to verify which votes belong to user. All
; call are run over GRPC and require the wallet GRPC certificate and wallet
; password.
; wallethost=localhost
; walletgrpccert=
; walletpassphrase=

; ------------------------------------------------------------------------------
; Debug
; ------------------------------------------------------------------------------

; Debug logging level.
; Valid levels are {trace, debug, info, warn, error, critical}
; You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set
; log level for individual subsystems.  Use dcrd --debuglevel=show to list
; available subsystems.
; debuglevel=info

; ------------------------------------------------------------------------------
; Profile - enable the HTTP profiler
; ------------------------------------------------------------------------------

; The profile server will be disabled if this option is not specified.  Profile
; information can be accessed at http://ipaddr:<profileport>/debug/pprof once
; running.  Note that the IP address will default to 127.0.0.1 if an IP address
; is not specified, so that the profiler is not accessible on the network.
; Listen on selected port on localhost only:
;   profile=6061
; Listen on selected port on all network interfaces:
;   profile=:6061
; Listen on single network ipv4 interface:
;   profile=192.168.1.123:6061
; Listen on ipv6 loopback interface:
;   profile=[::1]:6061
`
