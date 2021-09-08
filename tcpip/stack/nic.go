package stack

import (
	"sync"

	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
	"github.com/impact-eintr/netstack/tcpip/ilist"
)

// referenced 引用的
type referencedNetworkEndpoint struct {
	ilist.Entry // 一個侵入式链表
	refs        int32
	ep          NetworkEndpoint
	nic         *NIC
	protocol    tcpip.NetworkProtocolNumber

	// 如果为此协议启用了链接地址解析，则设置 linkCache。 否则设置为零。
	linkCache LinkAddressCache
	// holdInsertRef 受 NIC 的互斥锁保护。 它指示引用计数是否由于端点的插入而偏向 1。
	// 当在 NIC 上调用 RemoveAddress 时，它会重置为 false。
	holdsInserRef bool
}

// 代表一个网卡对象 network interface controller
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

// 添加当前的NIC到链路层设备，激活该NIC
func (n *NIC) attachLinkEndpint() {
	n.linkEP.Attach(n)
}

// 在NIC上添加addr地址 注册和初始化网络层协议
// 相当于给网卡添加ip地址
func (n *NIC) addAddressLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address,
	peb PrimaryEndpointBehavior, replace bool) (*referencedNetworkEndpoint, *tcpip.Error) {
	// 查看是否支持该协议 若不支持则返回错误
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		return nil, tcpip.ErrUnknowProtocol
	}

	// 比如netProto是ipv4 就会调用ipv4,NewEndpoint，新建一个网络层端
	ep, err := netProto.NewEndpoint(n.id, addr, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}

	// 获取网络层id 即ip地址
	id := *ep.ID()
	if ref, ok := n.endpoints[id]; ok {
		// 不是替换，且该id不存在，返回错误
		if !replace {
			return nil, tcpip.ErrDuplicateAddress // duplicate 复制的
		}
		n.removeEndpointLocked(ref)
	}

	ref := &referencedNetworkEndpoint{
		refs:          1,
		ep:            ep,
		nic:           n,
		protocol:      protocol,
		holdsInserRef: true,
	}

	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {

	}

	// 注册该网络端

}

// DeliverTransportPacket 将数据包传送到适当的传输协议端点。
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber,
	vv buffer.VectorisedView) {

}

// DeliverTransportControlPacket 将控制数据包传送到适当的传输协议端点。
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address,
	net tcpip.NetworkProtocolNumber, trans tcpip.TransportProtocolNumber,
	typ ControlType, extra uint32, vv buffer.VectorisedView) {

}
