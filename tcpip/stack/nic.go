package stack

import (
	"log"
	"netstack/ilist"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"strings"
	"sync"
	"sync/atomic"
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
	spoofing    bool                                        // 欺骗
	promiscuous bool                                        // 混杂模式
	primary     map[tcpip.NetworkProtocolNumber]*ilist.List // 网络协议号:网络端实现
	// 网络层端的记录 IP:网络端实现
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

// setPromiscuousMode enables or disables promiscuous mode.
// 设备网卡为混杂模式
func (n *NIC) setPromiscuousMode(enable bool) {
	n.mu.Lock()
	n.promiscuous = enable
	n.mu.Unlock()
}

// 判断网卡是否开启混杂模式
func (n *NIC) isPromiscuousMode() bool {
	n.mu.RLock()
	rv := n.promiscuous
	n.mu.RUnlock()
	return rv
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

	// 比如netProto是ipv4 会调用ipv4.NewEndpoint 新建一个网络端
	ep, err := netProto.NewEndpoint(n.id, addr, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}
	log.Printf("基于[%d]协议 为 #%d 网卡 添加网络层实现 并绑定地址到: %s\n", netProto.Number(), n.id, ep.ID().LocalAddress)

	// 获取网络层端的id 其实就是ip地址
	id := *ep.ID()
	if ref, ok := n.endpoints[id]; ok {
		// 不是替换 且该id已经存在
		if !replace {
			return nil, tcpip.ErrDuplicateAddress
		}
		n.removeEndpointLocked(ref) // 这里被调用的时候已经上过锁了 NOTE
	}

	ref := &referencedNetworkEndpoint{
		refs:           1,
		ep:             ep,
		nic:            n,
		protocol:       protocol,
		holdsInsertRef: true,
	}

	// Set up cache if link address resolution exists for this protocol.
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if _, ok := n.stack.linkAddrResolvers[protocol]; ok {
			ref.linkCache = n.stack
		}
	}

	// 注册该网络端
	n.endpoints[id] = ref

	l, ok := n.primary[protocol]
	if !ok {
		l = &ilist.List{}
		n.primary[protocol] = l
	}

	switch peb {
	case CanBePrimaryEndpoint:
		l.PushBack(ref) // 目前走这一支
	case FirstPrimaryEndpoint:
		l.PushFront(ref)
	}
	return ref, nil
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

// 删除一个网络端
func (n *NIC) removeEndpointLocked(r *referencedNetworkEndpoint) {
	id := *r.ep.ID()

	// Nothing to do if the reference has already been replaced with a
	// different one.
	if n.endpoints[id] != r {
		return
	}

	if r.holdsInsertRef {
		panic("Reference count dropped to zero before being removed")
	}

	delete(n.endpoints, id)
	wasInList := r.Next() != nil || r.Prev() != nil || r == n.primary[r.protocol].Front()
	if wasInList {
		n.primary[r.protocol].Remove(r)
	}

	r.ep.Close()
}

func (n *NIC) removeEndpoint(r *referencedNetworkEndpoint) {
	n.mu.Lock()
	n.removeEndpointLocked(r)
	n.mu.Unlock()
}

// primaryEndpoint returns the primary endpoint of n for the given network
// protocol.
// 根据网络层协议号找到对应的网络层端
func (n *NIC) primaryEndpoint(protocol tcpip.NetworkProtocolNumber) *referencedNetworkEndpoint {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := n.primary[protocol]
	if list == nil {
		return nil
	}

	for e := list.Front(); e != nil; e = e.Next() {
		r := e.(*referencedNetworkEndpoint)
		// TODO: allow broadcast address when SO_BROADCAST is set.
		switch r.ep.ID().LocalAddress {
		case header.IPv4Broadcast, header.IPv4Any:
			continue
		}
		if r.tryIncRef() {
			return r
		}
	}

	return nil
}

// 根据address参数找到对应的网络层端
func (n *NIC) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address,
	peb PrimaryEndpointBehavior) *referencedNetworkEndpoint {
	id := NetworkEndpointID{address}

	n.mu.RLock()
	ref := n.endpoints[id]
	if ref != nil && !ref.tryIncRef() { // 尝试去使用这个网络端实现
		ref = nil
	}
	spoofing := n.spoofing
	n.mu.RUnlock()

	if ref != nil || !spoofing {
		return ref
	}

	// Try again with the lock in exclusive mode. If we still can't get the
	// endpoint, create a new "temporary" endpoint. It will only exist while
	// there's a route through it.
	n.mu.Lock()
	ref = n.endpoints[id]
	if ref == nil || !ref.tryIncRef() {
		ref, _ = n.addAddressLocked(protocol, address, peb, true)
		if ref != nil {
			ref.holdsInsertRef = false
		}
	}
	n.mu.Unlock()
	return ref
}

// AddSubnet adds a new subnet to n, so that it starts accepting packets
// targeted at the given address and network protocol.
// AddSubnet向n添加一个新子网，以便它开始接受针对给定地址和网络协议的数据包。
func (n *NIC) AddSubnet(protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) {
	n.mu.Lock()
	n.subnets = append(n.subnets, subnet)
	n.mu.Unlock()
}

// RemoveSubnet removes the given subnet from n.
// 从n中删除一个子网
func (n *NIC) RemoveSubnet(subnet tcpip.Subnet) {
	n.mu.Lock()

	// Use the same underlying array.
	tmp := n.subnets[:0]
	for _, sub := range n.subnets {
		if sub != subnet {
			tmp = append(tmp, sub)
		}
	}
	n.subnets = tmp

	n.mu.Unlock()
}

// ContainsSubnet reports whether this NIC contains the given subnet.
// 判断 subnet 这个子网是否在该网卡下
func (n *NIC) ContainsSubnet(subnet tcpip.Subnet) bool {
	for _, s := range n.Subnets() {
		if s == subnet {
			return true
		}
	}
	return false
}

// Subnets returns the Subnets associated with this NIC.
// 获取该网卡的所有子网
func (n *NIC) Subnets() []tcpip.Subnet {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sns := make([]tcpip.Subnet, 0, len(n.subnets)+len(n.endpoints))
	for nid := range n.endpoints {
		sn, err := tcpip.NewSubnet(nid.LocalAddress, tcpip.AddressMask(strings.Repeat("\xff", len(nid.LocalAddress))))
		if err != nil {
			// This should never happen as the mask has been carefully crafted to
			// match the address.
			panic("Invalid endpoint subnet: " + err.Error())
		}
		sns = append(sns, sn)
	}
	return append(sns, n.subnets...)
}

// 根据协议类型和目标地址，找出关联的Endpoint
func (n *NIC) getRef(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) *referencedNetworkEndpoint {
	id := NetworkEndpointID{dst}

	n.mu.RLock()
	if ref, ok := n.endpoints[id]; ok && ref.tryIncRef() {
		log.Println("找到了目标网络层实现: ", id.LocalAddress)
		n.mu.RUnlock()
		return ref
	}

	promiscuous := n.promiscuous
	// Check if the packet is for a subnet this NIC cares about.
	if !promiscuous {
		for _, sn := range n.subnets {
			if sn.Contains(dst) {
				promiscuous = true
				break
			}
		}
	}
	n.mu.RUnlock()
	if promiscuous {
		// Try again with the lock in exclusive mode. If we still can't
		// get the endpoint, create a new "temporary" one. It will only
		// exist while there's a route through it.
		n.mu.Lock()
		if ref, ok := n.endpoints[id]; ok && ref.tryIncRef() {
			n.mu.Unlock()
			return ref
		}
		ref, err := n.addAddressLocked(protocol, dst, CanBePrimaryEndpoint, true)
		n.mu.Unlock()
		if err == nil {
			ref.holdsInsertRef = false
			return ref
		}
	}

	return nil
}

// 当 NIC 从物理接口接收数据包时，将调用函数 DeliverNetworkPacket，用来分发网络层数据包。
// 比如 protocol 是 arp 协议号，那么会找到arp.HandlePacket来处理数据报。
// 简单来说就是根据网络层协议和目的地址来找到相应的网络层端，将网络层数据发给它，
// 当前实现的网络层协议有 arp、ipv4 和 ipv6。
func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, remoteLinkAddr, localLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	if netProto.Number() == header.IPv4ProtocolNumber || netProto.Number() == header.IPv6ProtocolNumber {
		n.stack.stats.IP.PacketsReceived.Increment()
	}

	if len(vv.First()) < netProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	src, dst := netProto.ParseAddresses(vv.First())
	log.Printf("设备[%v]准备从 [%s] 向 [%s] 分发数据: %v\n", linkEP.LinkAddress(), src, dst, func() []byte {
		if len(vv.ToView()) > 64 {
			return vv.ToView()[:64]
		}
		return vv.ToView()
	}())
	// 根据网络协议和数据包的目的地址，找到网络端
	// 然后将数据包分发给网络层
	if ref := n.getRef(protocol, dst); ref != nil {
		r := makeRoute(protocol, dst, src, linkEP.LinkAddress(), ref)
		r.RemoteLinkAddress = remoteLinkAddr
		ref.ep.HandlePacket(&r, vv)
		ref.decRef()

		return
	}
	n.stack.stats.IP.InvalidAddressesReceived.Increment()
}

// DeliverTransportPacket delivers packets to the appropriate
// transport protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView) {
	log.Println("准备分发传输层数据报")

}

// DeliverTransportControlPacket delivers control packets to the
// appropriate transport protocol endpoint.
func (n *NIC) DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber,
	trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView) {

}

func (n *NIC) ID() tcpip.NICID {
	return n.id
}

// 网络端引用
type referencedNetworkEndpoint struct {
	ilist.Entry
	refs     int32           // 引用计数
	ep       NetworkEndpoint // 网络端实现
	nic      *NIC
	protocol tcpip.NetworkProtocolNumber

	// linkCache is set if link address resolution is enabled for this
	// protocol. Set to nil otherwise.
	linkCache LinkAddressCache
	linkAddrCache

	// holdsInsertRef is protected by the NIC's mutex. It indicates whether
	// the reference count is biased by 1 due to the insertion of the
	// endpoint. It is reset to false when RemoveAddress is called on the
	// NIC.
	holdsInsertRef bool
}

func (r *referencedNetworkEndpoint) decRef() {
	if atomic.AddInt32(&r.refs, -1) == 0 {
		r.nic.removeEndpoint(r)
	}
}

func (r *referencedNetworkEndpoint) incRef() {
	atomic.AddInt32(&r.refs, 1)
}

func (r *referencedNetworkEndpoint) tryIncRef() bool {
	for {
		v := atomic.LoadInt32(&r.refs)
		if v == 0 {
			return false
		}

		if atomic.CompareAndSwapInt32(&r.refs, v, v+1) {
			return true
		}
	}
}
