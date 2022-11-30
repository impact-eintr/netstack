package main

import (
	"flag"
	"log"
	"net"
	"os"

	"netstack/tcpip"
	"netstack/tcpip/link/fdbased"
	"netstack/tcpip/link/tuntap"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/stack"
)

// 链路层主要负责管理网卡和处理网卡数据，
// 包括新建网卡对象绑定真实网卡，更改网卡参数，接收网卡数据，去除以太网头部后分发给上层，接收上层数据，封装以太网头部写入网卡。
// 需要注意的是主机与主机之间的二层通信，也需要主机有 ip 地址，
// 因为主机需要通过 arp 表来进行二层寻址，而 arp 表记录的是 ip 与 mac 地址的映射关系，所以主机的 ip 地址是必须的。
// 经过上面的实验我们已经知道，只要配好路由，我们在系统发送的数据就都可以进入到 tap 网卡，
// 然后程序就可以读取到网卡数据，进行处理，实现对 arp 报文的处理，那如果我们继续处理 ip 报文、tcp 报文就可以实现整个协议栈了。
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
		[]string{}, stack.Options{})

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

	select {}
}
