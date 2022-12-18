package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"runtime"
	"strings"
	"sync/atomic"
)

// PID netstack PID
type PID uint16

var currPID uint32 = 1

// Socket in memory
type Socket struct { // 0 1 2 用过了
	socket *TcpConn
}

// FD file descriptor
type FD uint16

var fds = make(map[PID][]Socket, 8)

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
	rcvBuf []byte
}

func (r *RCV) Handle(conn net.Conn) {
	var err error
	_, err = conn.Read(r.rcvBuf)
	if err != nil && len(r.rcvBuf) < 1 { // 操作码
		panic(err)
	}

	switch r.rcvBuf[0] {
	case REGISTER:
		conn.Write(r.register())
		return
	case LISTEN:
		conn.Write(r.listen())
		return
	case ACCEPT:
		conn.Write(r.accept())
		return
	case CONNECT:
		goto FAULT
	case READ:
		conn.Write(r.read())
		return
	case WRITE:
		conn.Write(r.write())
		return
	case CLOSE:
		goto FAULT
	default:
		return
	}

FAULT:
	logger.NOTICE("FAULT")
}

func (r *RCV) listen() []byte {
	if len(r.rcvBuf) < 5 { // udp ip port
		log.Println("Error: too few arg")
		return nil
	}
	pid := binary.BigEndian.Uint16(r.rcvBuf[1:3])
	port := binary.BigEndian.Uint16(r.rcvBuf[3:5])

	listener := tcpListen(r.Stack, header.IPv4ProtocolNumber, "", int(port))

	for i, v := range fds[PID(pid)] {
		if i > 2 && v.socket == nil {
			fds[PID(pid)][i] = Socket{listener}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b[:2], uint16(i))
			return b
		}
	}
	panic("No Idle Space")
}

func (r *RCV) accept() []byte {
	if len(r.rcvBuf) < 5 { // udp ip port
		log.Println("Error: too few arg")
		return nil
	}
	pid := binary.BigEndian.Uint16(r.rcvBuf[1:3])
	lfd := binary.BigEndian.Uint16(r.rcvBuf[3:5])

	l := fds[PID(pid)][lfd]
	conn, err := l.socket.Accept()
	if err != nil {
		log.Println(err)
	}
	for i, v := range fds[PID(pid)] {
		if i > 2 && v.socket == nil {
			fds[PID(pid)][i] = Socket{conn}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b[:2], uint16(i))
			return b
		}
	}
	panic("No Idle Space")
}

func (r *RCV) connect() {
}

func (r *RCV) read() []byte {
	if len(r.rcvBuf) < 5 { // opc pid cfd
		log.Println("Error: too few arg")
		return nil
	}
	pid := binary.BigEndian.Uint16(r.rcvBuf[1:3])
	cfd := binary.BigEndian.Uint16(r.rcvBuf[3:5])

	c := fds[PID(pid)][cfd]
	buf := make([]byte, 1024)
	c.socket.Read(buf)
	return buf
}

func (r *RCV) write() []byte {
	if len(r.rcvBuf) < 9 { // opc pid cfd length
		log.Println("Error: too few arg")
		return nil
	}
	pid := binary.BigEndian.Uint16(r.rcvBuf[1:3])
	cfd := binary.BigEndian.Uint16(r.rcvBuf[3:5])
	length := binary.BigEndian.Uint32(r.rcvBuf[5:9])

	c := fds[PID(pid)][cfd]
	c.socket.Write(r.rcvBuf[9 : 9+length])
	return nil
}

func (r *RCV) close() {
}

// Register 注册pid
func (r *RCV) register() []byte {
	pid := uint16(atomic.AddUint32(&currPID, 1))
	fds[PID(pid)] = make([]Socket, 1024)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b[:2], pid)
	return b
}
