package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"

	iptbl "github.com/coreos/go-iptables/iptables"
	_dns "github.com/factorysh/on-his-name/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	opsCached = promauto.NewCounter(prometheus.CounterOpts{
		Name: "onhisname_cached_total",
		Help: "The total number of cached requests",
	})
	opsRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "onhisname_rejected_total",
		Help: "The total number of rejected requests",
	})
	opsAccepted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "onhisname_accepted_total",
		Help: "The total number of accepted requests",
	})
	ipsLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "onhisname_ips",
		Help: "The current number of accepted IPs",
	})
)

// Rule contrains a simple rule struct
type Rule struct {
	raw    string
	append bool
}

// Apply specified rule
func (r *Rule) Apply(handler *iptbl.IPTables) error {
	rspecs := strings.Split(r.raw, " ")

	if r.append {
		return handler.AppendUnique("filter", "DOCKER-USER", rspecs...)
	}

	// always put a new rule at the top
	// this may change later
	return handler.Insert("filter", "DOCKER-USER", 1, rspecs...)
}

type Firewall struct {
	names        chan *_dns.ResolvedName
	matcher      []string
	accepted     map[string]interface{}
	bridge       string
	outInterface string
	ipt          *iptbl.IPTables
}

func New(br string, matches ...string) (*Firewall, error) {
	f := &Firewall{
		names:        make(chan *_dns.ResolvedName),
		matcher:      matches,
		accepted:     make(map[string]interface{}),
		bridge:       br,
		outInterface: "docker0",
	}
	return f, nil
}

func (f *Firewall) Channel() chan *_dns.ResolvedName {
	return f.names
}

func (f *Firewall) Setup() (err error) {

	f.ipt, err = iptbl.New(iptbl.IPFamily(iptbl.ProtocolIPv4), iptbl.Timeout(0))
	if err != nil {
		return err
	}

	ok, err := f.ipt.ChainExists("filter", "DOCKER-USER")
	if err != nil {
		return err
	}
	// DOCKER-USER is created by docker daemon, let it do it
	if !ok {
		return fmt.Errorf("DOCKER-USER chain is missing in this iptables state")
	}

	// open port 53, tcp, udp
	// close the rest
	defaults := []Rule{
		{raw: "-m conntrack --ctstate ESTABLISHED -j ACCEPT", append: true},
		{raw: "-j DROP", append: true},
		{raw: fmt.Sprintf("-o %s -p tcp --dport 53 -j ACCEPT", f.bridge), append: false},
		{raw: fmt.Sprintf("-o %s -p udp --dport 53 -j ACCEPT", f.bridge), append: false},
	}

	for _, rule := range defaults {
		err := rule.Apply(f.ipt)
		if err != nil {
			return err
		}
	}

	return err
}

func (f *Firewall) Start(ctx context.Context) {
	for {
		select {
		case name := <-f.names:
			if name.A != nil {
				f.Filter(name.Cname, name.A)
			}
		case <-ctx.Done():
			break
		}
	}
}

func (f *Firewall) Filter(name string, ip net.IP) bool {
	if _, ok := f.accepted[ip.String()]; ok {
		fmt.Println("Already done", name)
		opsCached.Inc()
		return true
	}
	for _, r := range f.matcher {
		ok, err := path.Match(r, name)
		if err != nil {
			fmt.Println("Match error ", err)
			continue
		}
		if ok {
			err := f.Allow(ip)
			if err != nil {
				// TODO: better error handling, just log for now
				fmt.Println(err)
			}
			f.accepted[ip.String()] = name
			ipsLen.Set(float64(len(f.accepted)))
			opsAccepted.Inc()
			fmt.Println("Do", name)
			return true
		}
	}
	opsRejected.Inc()
	fmt.Println("Ban", name)
	return false
}

func (f *Firewall) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/matchers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.matcher)
	})
	mux.HandleFunc("/api/accepted", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ips := make([]string, len(f.accepted))
		i := 0
		for k, _ := range f.accepted {
			ips[i] = k
			i++
		}
		sort.Sort(sort.StringSlice(ips))
		json.NewEncoder(w).Encode(ips)
	})
}
