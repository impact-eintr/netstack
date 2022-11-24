package stack

import (
	"netstack/ilist"
	"netstack/tcpip"
	"sync"
)

// 代表一个网卡对象 当我们创建好tap网卡对象后 我们使用NIC来代表它在我们自己的协议栈中的网卡对象
type NIC struct {
	stack *Stack
	// 每个网卡的惟一标识号
	id tcpip.NICID
	// 网卡名，可有可无
	name string
	// 链路层端
	linkEP LinkEndpoint // 在链路层 这就是 fdbased.endpoint

	// 传输层的解复用
	demux *transportDemuxer

	mu          sync.RWMutex
	spoofing    bool
	promiscuous bool // 混杂模式
	primary     map[tcpip.NetworkProtocolNumber]*ilist.List
	// 网络层端的记录
	endpoints map[NetworkEndpoingID]*referencedNetworkEndpoint
	// 子网的记录
	subnets []tcpip.Subnet
}
