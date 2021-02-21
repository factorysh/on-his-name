package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	dnstap "github.com/dnstap/golang-dnstap"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

func main() {

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = "localhost:4807"
	}

	if strings.HasPrefix(listen, "/") || strings.HasPrefix(listen, "./") {
		i, err := dnstap.NewFrameStreamSockInputFromPath(listen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input socket %s: %v\n", listen, err)
			os.Exit(1)
		}
		i.SetLogger(logger)
	} else {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			panic(err)
		}
		i := dnstap.NewFrameStreamSockInput(l)
		//i.SetTimeout(*flagTimeout)
		i.SetLogger(logger)
	}
}
