package stack

import (
	"log"
	"netstack/ilist"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"sync"
)

// PrimaryEndpointBehavior 是端点首要行为的枚举
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address. This is the
	// default when calling NIC.AddAddress.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, the most recently-added one will be first.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
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
	endpoints map[NetworkEndpointID]*referencedNetworkEndpoint
	// 子网的记录
	subnets []tcpip.Subnet
}

// 创建新的网卡对象
func newNIC(stack *Stack, id tcpip.NICID, name string, ep LinkEndpoint) *NIC {
	return &NIC{
		stack:     stack,
		id:        id,
		name:      name,
		linkEP:    ep,
		demux:     nil, // TODO 需要处理
		primary:   make(map[tcpip.NetworkProtocolNumber]*ilist.List),
		endpoints: make(map[NetworkEndpointID]*referencedNetworkEndpoint),
	}
}

func (n *NIC) attachLinkEndpoint() {
	n.linkEP.Attach(n)
}

// 在NIC上添加addr地址，注册和初始化网络层协议
// 相当于给网卡添加ip地址
func (n *NIC) addAddressLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address,
	peb PrimaryEndpointBehavior, replace bool) (*referencedNetworkEndpoint, *tcpip.Error) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		log.Println("添加失败")
		return nil, tcpip.ErrUnknownProtocol
	}
	log.Println(netProto.Number(), "添加ip", addr.String())
	// TODO 接着这里实现 22/11/24 21:29
	return nil, nil
}

func (n *NIC) AddAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	return n.AddAddressWithOptions(protocol, addr, CanBePrimaryEndpoint)
}

func (n *NIC) AddAddressWithOptions(protocol tcpip.NetworkProtocolNumber,
	addr tcpip.Address, peb PrimaryEndpointBehavior) *tcpip.Error {
	n.mu.Lock()
	_, err := n.addAddressLocked(protocol, addr, peb, false)
	n.mu.Unlock()

	return err
}

func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	// TODO 需要完成逻辑
	log.Println(vv.ToView())
}
