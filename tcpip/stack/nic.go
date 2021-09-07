package stack

import (
	"sync"

	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/ilist"
)

type referencedNetworkEndpoint struct {
	//ilist.Entry
	//refs     int32
	//ep       NetworkEndpoint
	//nic      *NIC
	//protocol tcpip.NetworkProtocolNumber
	//linkCache LinkAddressCache
	//holdsInserRef bool
}

// 代表一个网卡对象
type NIC struct {
	stack *Stack
	// 每个网卡唯一的标识号
	id tcpip.NICID
	// 网卡名 可有可无
	name string
	// 链路层端
	linkEP LinkEndpoint
	// 传输层的解复用
	demux *transportDemuxer

	mu          sync.RWMutex
	spoofing    bool
	promiscuous bool
	primary     map[tcpip.NetworkProtocolNumber]*ilist.List
	// 网络层端的记录
	endpoints map[NetworkEndpointID]*referencedNetworkEndpoint
	// 子网的记录
	subnets []tcpip.Subnet
}

// 根据参数新建一个NIC
func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint) *NIC {
	return &NIC{
		stack:     stack,
		id:        id,
		name:      name,
		linkEP:    ep,
		demux:     newTransportDemuxer(stack),
		primary:   make(map[tcpip.NetworkProtocolNumber]*ilist.List),
		endpoints: make(map[NetworkEndpointID]*referencedNetworkEndpoint),
	}
}

type NetworkEndpointID struct {
	LocalAddress tcpip.Address
}
