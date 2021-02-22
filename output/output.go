package output

import (
	"fmt"
	"log"

	dnstap "github.com/dnstap/golang-dnstap"
	_dns "github.com/factorysh/on-his-name/dns"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

type Output struct {
	output   chan []byte
	log      *log.Logger
	done     chan struct{}
	resolved chan *_dns.ResolvedName
}

func New(l *log.Logger, resolved chan *_dns.ResolvedName) *Output {
	return &Output{
		output:   make(chan []byte, 32),
		log:      l,
		done:     make(chan struct{}),
		resolved: resolved,
	}
}

func (o *Output) GetOutputChannel() chan []byte {
	return o.output
}

func (o *Output) RunOutputLoop() {
	/*
		sigch := make(chan os.Signal, 1)
		signal.Notify(sigch, os.Interrupt, syscall.SIGHUP)
	*/
	dt := &dnstap.Dnstap{}
	for frame := range o.output {
		if err := proto.Unmarshal(frame, dt); err != nil {
			o.log.Print(err)
			break
		}
		m := dt.GetMessage()
		switch *dt.Message.Type {
		case dnstap.Message_CLIENT_QUERY:
			msg := new(dns.Msg)
			if err := msg.Unpack(m.GetQueryMessage()); err != nil {
				o.log.Print(err)
				break
			}
			for _, q := range msg.Question {
				fmt.Println("Query", q)
			}
		case dnstap.Message_CLIENT_RESPONSE:
			msg := new(dns.Msg)
			if err := msg.Unpack(m.GetResponseMessage()); err != nil {
				o.log.Print(err)
				break
			}
			rn := &_dns.ResolvedName{}
			for _, r := range msg.Answer {
				fmt.Println("Response", r.Header().Name,
					dns.Class(r.Header().Class), dns.Type(r.Header().Rrtype),
					r)
				switch r.Header().Rrtype {
				case dns.TypeCNAME:
					rr, ok := r.(*dns.CNAME)
					if ok {
						fmt.Println("CNAME target", rr.Target)
						rn.Cname = rr.Target
					}
				case dns.TypeA:
					rr, ok := r.(*dns.A)
					if ok {
						fmt.Println("A", rr.A)
						rn.A = rr.A
					}
				}
			}
			o.resolved <- rn
		}
	}
}

func (o *Output) Close() {
	close(o.output)
	<-o.done
}
