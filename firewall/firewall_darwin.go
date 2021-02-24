package firewall

import (
	"fmt"
	"net"
)

func (f *Firewall) Deny(ip net.IP) error {
	fmt.Println(ip)
	return nil
}
