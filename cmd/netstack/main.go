package main

import (
	"flag"
	"log"
	"net"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/link/fdbased"
	"netstack/tcpip/link/loopback"
	"netstack/tcpip/link/tuntap"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/network/ipv6"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/tcp"
	"netstack/tcpip/transport/udp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
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

	_ = linkID

	loopbackLinkID := loopback.New()

	// 新建相关协议的协议栈
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName},
		[]string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	// 新建抽象的网卡
	if err := s.CreateNamedNIC(1, "vnic1", loopbackLinkID); err != nil {
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

	done := make(chan struct{}, 2)

	//logger.SetFlags(logger.TCP)
	go func() { // echo server
		//time.Sleep(1 * time.Second)
		//pid := Register()
		//log.Fatal(pid)

		listener := tcpListen(s, proto, addr, localPort)
		done <- struct{}{}
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println(err)
			}
			log.Println("服务端 建立连接")

			go func() {
				for {
					// 一个慢读者 才能体现出网络的情况
					time.Sleep(500 * time.Millisecond)
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					if err != nil {
						log.Println(n, err)
						break
					}
					logger.NOTICE("服务端读取了数据", string(buf))
					//conn.Write([]byte("Hello Client"))
				}
			}()
		}
	}()

	go func() {
		<-done
		logger.NOTICE("客户端上线")
		port := localPort
		conn, err := Dial(s, header.IPv4ProtocolNumber, addr, port)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("客户端 建立连接\n")

		conn.SetSockOpt(tcpip.KeepaliveEnabledOption(1))
		conn.SetSockOpt(tcpip.KeepaliveIntervalOption(75 * time.Second))
		conn.SetSockOpt(tcpip.KeepaliveIdleOption(30 * time.Second)) // 30s的探活心跳
		conn.SetSockOpt(tcpip.KeepaliveCountOption(9))

		log.Printf("\n\n客户端 写入数据")

		for i := 0; i < 1; i++ {
			conn.Write(make([]byte, 1<<20))

			//buf := make([]byte, 1024)
			//n, err := conn.Read(buf)
			//if err != nil {
			//	log.Println(err)
			//	break
			//}
			//logger.NOTICE(string(buf[:n]))
			time.Sleep(5 * time.Millisecond)
		}

		select {}
		conn.Close()
	}()

	//l, err := net.Listen("tcp", "127.0.0.1:9999")
	//if err != nil {
	//	fmt.Println("Error listening:", err)
	//	os.Exit(1)
	//}
	//rcv := &RCV{
	//	Stack:  s,
	//	rcvBuf: make([]byte, 1<<20),
	//}

	//TCPServer(l, rcv)

	defer close(done)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
	<-c
}
