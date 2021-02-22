package dns

import "net"

type ResolvedName struct {
	Cname string
	A     net.IP
}
