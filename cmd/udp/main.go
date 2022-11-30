package main

import (
	"flag"
	"log"
	"net"
	"netstack/tcpip"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/udp"
	"netstack/waiter"
	"os"
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatal("Usage: ", os.Args[0], "<listen-address> port")
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	listeAddr := flag.Arg(0)
	portName := flag.Arg(1)

	Socket(listeAddr + ":" + portName)
}

func Socket(addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	conn.Write([]byte("udp\xc0\xa8\x01\x01\x27\x0f")) // bind udp 192.168.1.1 9999
	conn.Close()
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
