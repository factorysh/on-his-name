package firewall

import (
	"net"
	"regexp"
)

type Firewall struct {
	matcher  []*regexp.Regexp
	accepted map[string]interface{}
}

func New(regex ...string) (*Firewall, error) {
	f := &Firewall{
		matcher:  make([]*regexp.Regexp, len(regex)),
		accepted: make(map[string]interface{}),
	}
	for i, r := range regex {
		rr, err := regexp.CompilePOSIX(r)
		if err != nil {
			return nil, err
		}
		f.matcher[i] = rr
	}
	return f, nil
}

func (f *Firewall) Filter(name string, ip net.IP) bool {
	if _, ok := f.accepted[ip.String()]; ok {
		return true
	}
	for _, r := range f.matcher {
		if r.Match([]byte(name)) {
			f.Add(ip)
			f.accepted[ip.String()] = name
			return true
		}
	}
	return false
}
