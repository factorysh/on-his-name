package firewall

import (
	"fmt"
	"net"
)

func (f *Firewall) Allow(ip net.IP) error {
	allowHTTP := []Rule{
		{raw: fmt.Sprintf("-p tcp -i %s --dport 80 -d %s -j ACCEPT", f.outInterface, ip.String()), append: false},
		{raw: fmt.Sprintf("-p tcp -i %s --dport 443 -d %s -j ACCEPT", f.outInterface, ip.String()), append: false},
	}

	for _, rule := range allowHTTP {
		err := rule.Apply(f.ipt)
		if err != nil {
			return err
		}
	}

	return nil

}
