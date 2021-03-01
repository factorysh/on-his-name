package firewall

import (
	"fmt"
	"net"
)

func (f *Firewall) Allow(ip net.IP) error {
	fmt.Println(ip)
	return nil
}
