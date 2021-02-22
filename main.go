package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	_dns "github.com/factorysh/on-his-name/dns"
	"github.com/factorysh/on-his-name/firewall"
	"github.com/factorysh/on-his-name/output"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

func main() {

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = "localhost:4807"
	}

	fw, err := firewall.New(os.Args[1:]...)
	if err != nil {
		panic(err)
	}
	resolved := make(chan *_dns.ResolvedName)

	go fw.Start(context.Background())
	o := output.New(logger, fw.Channel())
	go func() {
		for {
			r := <-resolved
			fmt.Println("Patch your firewall with", r.Cname, r.A)
		}
	}()
	go o.RunOutputLoop()
	if strings.HasPrefix(listen, "/") || strings.HasPrefix(listen, "./") {
		i, err := dnstap.NewFrameStreamSockInputFromPath(listen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input socket %s: %v\n", listen, err)
			os.Exit(1)
		}
		i.SetTimeout(10 * time.Second)
		i.SetLogger(logger)
		fmt.Println("Listening UNIX", listen)
		i.ReadInto(o.GetOutputChannel())
	} else {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			panic(err)
		}
		fmt.Println("Listening", listen)
		i := dnstap.NewFrameStreamSockInput(l)
		i.SetTimeout(10 * time.Second)
		i.SetLogger(logger)
		i.ReadInto(o.GetOutputChannel())
	}

}
