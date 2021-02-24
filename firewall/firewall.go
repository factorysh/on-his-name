package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"sort"

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

type Firewall struct {
	names    chan *_dns.ResolvedName
	matcher  []string
	accepted map[string]interface{}
	br       string
}

func New(br string, matches ...string) (*Firewall, error) {
	f := &Firewall{
		names:    make(chan *_dns.ResolvedName),
		matcher:  matches,
		accepted: make(map[string]interface{}),
		br:       br,
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
			f.Add(ip)
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
