package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
)

type TCPHandler interface {
	Handle(net.Conn)
}

func TCPServer(listener net.Listener, handler TCPHandler, logf lg.AppLogFunc) error {
	log.Printf("TCP: listening on %s", listener.Addr())

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				log.Printf("temporary Accept() failure - %s", err)
				runtime.Gosched()
				continue
			}
			// theres no direct way to detect this error because it is not exposed
			if !strings.Contains(err.Error(), "use of closed network connection") {
				return fmt.Errorf("listener.Accept() error - %s", err)
			}
			break
		}
		go handler.Handle(clientConn)
	}

	log.Printf("TCP: closing %s", listener.Addr())

	return nil
}
