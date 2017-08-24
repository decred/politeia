package util

import (
	"net"
	"os"
	"strings"
)

// FQDN returns the fully qualified domain name of the machine it is running
// on.
func FQDN() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, ".")
		}
	}

	return hostname
}
