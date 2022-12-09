package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/link/fdbased"
	"netstack/tcpip/link/tuntap"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/network/ipv6"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/tcp"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")

func main() {
	flag.Parse()
	if len(flag.Args()) != 4 {
		log.Fatal("Usage: ", os.Args[0], " <tap-device> <local-address/mask> <ip-address> <local-port>")
	}

	logger.SetFlags(logger.HANDSHAKE)
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	tapName := flag.Arg(0)
	cidrName := flag.Arg(1)
	addrName := flag.Arg(2)
	portName := flag.Arg(3)

	log.Printf("tap: %v, addr: %v, port: %v", tapName, addrName, portName)

	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	parsedAddr := net.ParseIP(addrName)
	if err != nil {
		log.Fatalf("Bad addrress: %v", addrName)
	}

	// 解析地址ip地址，ipv4或者ipv6地址都支持
	var addr tcpip.Address
	var proto tcpip.NetworkProtocolNumber
	if parsedAddr.To4() != nil {
		addr = tcpip.Address(parsedAddr.To4())
		proto = ipv4.ProtocolNumber
	} else if parsedAddr.To16() != nil {
		addr = tcpip.Address(parsedAddr.To16())
		proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown IP type: %v", parsedAddr)
	}

	localPort, err := strconv.Atoi(portName)
	if err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	}

	// 虚拟网卡配置
	conf := &tuntap.Config{
		Name: tapName,
		Mode: tuntap.TAP,
	}

	var fd int
	// 新建虚拟网卡
	fd, err = tuntap.NewNetDev(conf)
	if err != nil {
		log.Fatal(err)
	}

	// 启动tap网卡
	_ = tuntap.SetLinkUp(tapName)
	// 设置路由
	_ = tuntap.SetRoute(tapName, cidrName)

	// 抽象的文件接口
	linkID := fdbased.New(&fdbased.Options{
		FD:                 fd,
		MTU:                1500,
		Address:            tcpip.LinkAddress(maddr),
		ResolutionRequired: true,
	})

	// 新建相关协议的协议栈
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName},
		[]string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	// 新建抽象的网卡
	if err := s.CreateNamedNIC(1, "vnic1", linkID); err != nil {
		log.Fatal(err)
	}

	// 在该协议栈上添加和注册相应的网络层
	if err := s.AddAddress(1, proto, addr); err != nil {
		log.Fatal(err)
	}

	// 在该协议栈上添加和注册ARP协议
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}

	// 添加默认路由
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", len(addr))),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", len(addr))),
			Gateway:     "",
			NIC:         1,
		},
	})

	//logger.SetFlags(logger.TCP)
	go func() { // echo server
		listener := tcpListen(s, proto, addr, localPort)
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
		}

		for {
			buf := make([]byte, 1024)
			if _, err := conn.Read(buf); err != nil {
				log.Fatal(err)
			}
			fmt.Println(string(buf))
			//if string(buf) != "" {
			//	conn.Write([]byte("Server echo"))
			//}
		}
		os.Exit(1)

		select {}
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
	<-c
}

type TcpConn struct {
	raddr    tcpip.FullAddress
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	we       *waiter.Entry
	notifyCh chan struct{}
}

func (conn *TcpConn) Read(rcv []byte) (int, error) {
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

func (conn *TcpConn) Write(snd []byte) error {
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

// Listener tcp连接监听器
type Listener struct {
	raddr    tcpip.FullAddress
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	we       *waiter.Entry
	notifyCh chan struct{}
}

// Accept 封装tcp的accept操作
func (l *Listener) Accept() (*TcpConn, error) {
	l.wq.EventRegister(l.we, waiter.EventIn)
	defer l.wq.EventUnregister(l.we)
	for {
		ep, wq, err := l.ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-l.notifyCh
				continue
			}
			return nil, fmt.Errorf("%s", err.String())
		}
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		return &TcpConn{ep: ep,
			wq:       wq,
			we:       &waitEntry,
			notifyCh: notifyCh}, nil
	}
}

func tcpListen(s *stack.Stack, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, localPort int) *Listener {
	var wq waiter.Queue
	// 新建一个tcp端
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(err)
	}

	// 绑定IP和端口，这里的IP地址为空，表示绑定任何IP
	// 此时就会调用端口管理器
	if err := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: addr, Port: uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	// 开始监听
	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	return &Listener{
		ep:       ep,
		wq:       &wq,
		we:       &waitEntry,
		notifyCh: notifyCh}
}

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
