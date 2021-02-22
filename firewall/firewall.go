package firewall

import (
	"context"
	"fmt"
	"net"
	"regexp"

	_dns "github.com/factorysh/on-his-name/dns"
)

type Firewall struct {
	names    chan *_dns.ResolvedName
	matcher  []*regexp.Regexp
	accepted map[string]interface{}
}

func New(regex ...string) (*Firewall, error) {
	f := &Firewall{
		names:    make(chan *_dns.ResolvedName),
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

func (f *Firewall) Channel() chan *_dns.ResolvedName {
	return f.names
}

func (f *Firewall) Start(ctx context.Context) {
	for {
		select {
		case name := <-f.names:
			f.Filter(name.Cname, name.A)
		case <-ctx.Done():
			break
		}
	}
}

func (f *Firewall) Filter(name string, ip net.IP) bool {
	if _, ok := f.accepted[ip.String()]; ok {
		fmt.Println("Already done", name)
		return true
	}
	for _, r := range f.matcher {
		if r.Match([]byte(name)) {
			f.Add(ip)
			f.accepted[ip.String()] = name
			fmt.Println("Do", name)
			return true
		}
	}
	fmt.Println("Ban", name)
	return false
}
