package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/stack"
	"runtime"
	"strings"
	"sync/atomic"
)

// PID netstack PID
type PID uint16

var currPID uint32 = 2 // 0 1 2 用过了

type FD uint16

var fds = make(map[PID][1024]FD, 8)

type TCPHandler interface {
	Handle(net.Conn)
}

func TCPServer(listener net.Listener, handler TCPHandler) error {
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
	logger.NOTICE("RCV handle")
	var err error
	r.rcvBuf, err = io.ReadAll(conn)
	if err != nil && len(r.rcvBuf) < 1 { // 操作码
		panic(err)
	}

	logger.NOTICE("注意测试")

	switch r.rcvBuf[0] {
	case REGISTER:
		conn.Write(r.Register())
	case LISTEN:
		goto FAULT
	case CONNECT:
		goto FAULT
	case READ:
		goto FAULT
	case WRITE:
		goto FAULT
	case CLOSE:
		goto FAULT
	default:
		return
	}

FAULT:
	logger.NOTICE("FAULT")
}

func (r *RCV) Listen() {
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

func (r *RCV) Register() []byte {
	pid := uint16(atomic.AddUint32(&currPID, 1))
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b[:2], pid)
	return b
}
