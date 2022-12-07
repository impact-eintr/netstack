package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
	"runtime"
	"strings"
)

type TCPHandler interface {
	Handle(net.Conn)
}

func TCPServer(listener net.Listener, handler TCPHandler) error {
	log.Printf("netstack 网络解析地址: %s", listener.Addr())

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

var transportPool = make(map[uint64]tcpip.Endpoint)

type RCV struct {
	*stack.Stack
	ep     tcpip.Endpoint
	addr   tcpip.FullAddress
	rcvBuf []byte
}

func (r *RCV) Handle(conn net.Conn) {
	var err error
	r.rcvBuf, err = io.ReadAll(conn)
	if err != nil && len(r.rcvBuf) < 9 { // proto + ip + port
		panic(err)
	}

	switch string(r.rcvBuf[:3]) {
	case "udp":
		var wq waiter.Queue
		// 新建一个udp端
		ep, err := r.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
		if err != nil {
			log.Fatal(err)
		}
		r.ep = ep
		r.Bind()
		r.Connect()
		r.Close()
	case "tcp":
	default:
		return
	}
}

func (r *RCV) Bind() {
	if len(r.rcvBuf) < 9 { // udp ip port
		log.Println("Error: too few arg")
		return
	}
	port := binary.BigEndian.Uint16(r.rcvBuf[7:9])
	r.addr = tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(r.rcvBuf[3:7]),
		Port: port,
	}
	r.ep.Bind(r.addr, nil)
}

func (r *RCV) Connect() {
	r.ep.Connect(tcpip.FullAddress{NIC: 1, Addr: "\xc0\xa8\x01\x02", Port: 8888})
}

func (r *RCV) Close() {
	r.ep.Close()
}
