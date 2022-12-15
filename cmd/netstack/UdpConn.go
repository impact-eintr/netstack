package main

import (
	"fmt"
	"log"
	"netstack/tcpip"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
)

type UdpConn struct {
	raddr    tcpip.FullAddress
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	we       *waiter.Entry
	notifyCh chan struct{}
}

func (conn *UdpConn) Close() {
	conn.ep.Close()
}

func (conn *UdpConn) Read(rcv []byte) (int, error) {
	conn.wq.EventRegister(conn.we, waiter.EventIn)
	defer conn.wq.EventUnregister(conn.we)
	for {
		buf, _, err := conn.ep.Read(&conn.raddr)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-conn.notifyCh
				continue
			}
			return 0, fmt.Errorf("%s", err.String())
		}
		n := len(buf)
		if n > cap(rcv) {
			n = cap(rcv)
		}
		rcv = append(rcv[:0], buf[:n]...)
		return n, nil
	}
}

func (conn *UdpConn) Write(snd []byte) error {
	for {
		_, notifyCh, err := conn.ep.Write(tcpip.SlicePayload(snd), tcpip.WriteOptions{To: &conn.raddr})
		if err != nil {
			if err == tcpip.ErrNoLinkAddress {
				<-notifyCh
				continue
			}
			return fmt.Errorf("%s", err.String())
		}
		return nil
	}
}

func udpListen(s *stack.Stack, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, localPort int) *UdpConn {
	var wq waiter.Queue
	// 新建一个udp端
	ep, err := s.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(err)
	}

	// 绑定IP和端口，这里的IP地址为空，表示绑定任何IP
	// 0.0.0.0:9999 这台机器上的所有ip的9999段端口数据都会使用该传输层实现
	// 此时就会调用端口管理器
	if err := ep.Bind(tcpip.FullAddress{NIC: 0, Addr: addr, Port: uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	return &UdpConn{
		ep:       ep,
		wq:       &wq,
		we:       &waitEntry,
		notifyCh: notifyCh}
}
