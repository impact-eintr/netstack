package main

import (
	"flag"
	"log"
	"net"
	"netstack/tcpip"
	"netstack/tcpip/link/fdbased"
	"netstack/tcpip/link/tuntap"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/network/ipv6"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
	"os"
	"strconv"
	"strings"
)

var mac = flag.String("mac", "01:01:01:01:01:01", "mac address to use in tap device")

func main() {
	flag.Parse()
	if len(flag.Args()) != 3 {
		log.Fatal("Usage: ", os.Args[0], " <tap-device> <listen-address> port")
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	tapName := flag.Arg(0)
	listeAddr := flag.Arg(1)
	portName := flag.Arg(2)

	log.Printf("tap: %v, listeAddr: %v, portName: %v", tapName, listeAddr, portName)

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

	parsedAddr := net.ParseIP(listeAddr)

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
	// 设置tap网卡IP地址
	_ = tuntap.AddIP(tapName, listeAddr)

	// 抽象网卡的文件接口
	linkID := fdbased.New(&fdbased.Options{
		FD:      fd,
		MTU:     1500,
		Address: tcpip.LinkAddress(maddr),
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

	// 同时监听tcp和udp localPort端口
	//tcpEp := tcpListen(s, proto, localPort)
	udpEp := udpListen(s, proto, localPort)
	// 关闭监听服务，此时会释放端口
	//tcpEp.Close()
	udpEp.Close()
}

//func tcpListen(s *stack.Stack, proto tcpip.NetworkProtocolNumber, localPort int) tcpip.Endpoint {
//	var wq waiter.Queue
//	// 新建一个tcp端
//	ep, err := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// 绑定IP和端口，这里的IP地址为空，表示绑定任何IP
//	// 此时就会调用端口管理器
//	if err := ep.Bind(tcpip.FullAddress{0, "", uint16(localPort)}, nil); err != nil {
//		log.Fatal("Bind failed: ", err)
//	}
//
//	// 开始监听
//	if err := ep.Listen(10); err != nil {
//		log.Fatal("Listen failed: ", err)
//	}
//
//	return ep
//}

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

	if err := ep.Connect(tcpip.FullAddress{NIC: 0, Addr: "", Port: uint16(localPort)}); err != nil {
		log.Fatal("Conn failed: ", err)
	}

	// 注意UDP是无连接的，它不需要Listen
	return ep
}
