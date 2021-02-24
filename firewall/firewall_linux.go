package firewall

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
	iptbl "github.com/coreos/go-iptables/iptables"
)

func (f *Firewall) Deny(ip net.IP) error {
	ipt, err := iptbl.New(iptbl.IPFamily(iptbl.ProtocolIPv4), iptables.Timeout(0))
	if err != nil {
		return err
	}

	ok, err := ipt.ChainExists("filter", "DOCKER-USER")

	fmt.Println("debug", ok, err)

	return err
}
