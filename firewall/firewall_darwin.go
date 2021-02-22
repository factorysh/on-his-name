package firewall

import (
	"fmt"
	"net"
)

func (f *Firewall) Add(ip net.IP) {
	fmt.Println(ip)
}
