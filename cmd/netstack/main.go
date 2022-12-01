package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/link/fdbased"
	"netstack/tcpip/link/tuntap"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
	"os"
	"strings"
	"time"
)

func main() {
	flag.Parse()
	if len(flag.Args()) < 2 {
		log.Fatal("Usage: ", os.Args[0], " <tap-device> <local-address/mask>")
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	tapName := flag.Arg(0)
	cidrName := flag.Arg(1)

	log.Printf("tap: %v, cidrName: %v", tapName, cidrName)

	parsedAddr, cidr, err := net.ParseCIDR(cidrName)
	if err != nil {
		log.Fatalf("Bad cidr: %v", cidrName)
	}

	// 解析地址ip地址，ipv4或者ipv6地址都支持
	var addr tcpip.Address
	var proto tcpip.NetworkProtocolNumber
	if parsedAddr.To4() != nil {
		addr = tcpip.Address(parsedAddr.To4())
		proto = ipv4.ProtocolNumber
	} else if parsedAddr.To16() != nil {
		addr = tcpip.Address(parsedAddr.To16())
		//proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown IP type: %v", parsedAddr)
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
	tuntap.SetLinkUp(tapName)
	// 设置路由
	tuntap.SetRoute(tapName, cidr.String())

	// 获取mac地址
	mac, err := tuntap.GetHardwareAddr(tapName)
	if err != nil {
		panic(err)
	}

	// 抽象网卡的文件接口
	linkID := fdbased.New(&fdbased.Options{
		FD:      fd,
		MTU:     1500,
		Address: tcpip.LinkAddress(mac),
	})
	// 新建相关协议的协议栈
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName},
		[]string{ /*tcp.ProtocolName, */ udp.ProtocolName}, stack.Options{})

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

	go func() {
		// 监听udp localPort端口
		udpEp := udpListen(s, proto, 9999)

		for {
			buf, _, err := udpEp.Read(nil)
			if err != nil {
				if err == tcpip.ErrWouldBlock {
					time.Sleep(100 * time.Millisecond)
					log.Println("阻塞中")
					continue
				}
			}
			log.Println(buf)
			break
		}
		// 关闭监听服务，此时会释放端口
		udpEp.Close()
	}()

	conn, _ := net.Listen("tcp", "0.0.0.0:9999")
	rcv := &RCV{
		Stack: s,
		addr:  tcpip.FullAddress{},
	}
	TCPServer(conn, rcv)
}

func udpListen(s *stack.Stack, proto tcpip.NetworkProtocolNumber, localPort int) tcpip.Endpoint {
	var wq waiter.Queue
	// 新建一个udp端
	ep, err := s.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(err)
	}

	// 绑定IP和端口，这里的IP地址为空，表示绑定任何IP
	// 0.0.0.0:9999 这台机器上的所有ip的9999段端口数据都会使用该传输层实现
	// 此时就会调用端口管理器
	if err := ep.Bind(tcpip.FullAddress{NIC: 0, Addr: "", Port: uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	// 注意UDP是无连接的，它不需要Listen
	return ep
}

type RCV struct {
	*stack.Stack
	ep     tcpip.Endpoint
	addr   tcpip.FullAddress
	rcvBuf []byte
}

var transportPool = make(map[uint64]tcpip.Endpoint)

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
