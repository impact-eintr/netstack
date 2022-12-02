package stack

import (
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
)

// 贯穿整个协议栈的路由，也就是在链路层和网络层都可以路由
// 如果目标地址是链路层地址，那么在链路层路由，
// 如果目标地址是网络层地址，那么在网络层路由。
type Route struct {
	// 远端网络层地址 ipv4 or ipv6 地址
	RemoteAddress tcpip.Address
	// 远端网卡MAC地址
	RemoteLinkAddress tcpip.LinkAddress

	// 本地网络层地址 ipv4 or ipv6 地址
	LocalAddress tcpip.Address
	// 本地网卡MAC地址
	LocalLinkAddress tcpip.LinkAddress

	// 下一跳网络层地址
	NextHop tcpip.Address

	// 网络层协议号
	NetProto tcpip.NetworkProtocolNumber

	// 相关的网络终端
	ref *referencedNetworkEndpoint
}

// 根据参数新建一个路由，并关联一个网络层端
func makeRoute(netProto tcpip.NetworkProtocolNumber, localAddr, remoteAddr tcpip.Address,
	localLinkAddr tcpip.LinkAddress, ref *referencedNetworkEndpoint) Route {
	return Route{
		NetProto:         netProto,
		LocalAddress:     localAddr,
		LocalLinkAddress: localLinkAddr,
		RemoteAddress:    remoteAddr,
		ref:              ref,
	}
}

// NICID returns the id of the NIC from which this route originates.
func (r *Route) NICID() tcpip.NICID {
	return r.ref.ep.NICID()
}

// MaxHeaderLength forwards the call to the network endpoint's implementation.
func (r *Route) MaxHeaderLength() uint16 {
	return r.ref.ep.MaxHeaderLength()
}

// Stats returns a mutable copy of current stats.
func (r *Route) Stats() tcpip.Stats {
	return r.ref.nic.stack.Stats()
}

// PseudoHeaderChecksum forwards the call to the network endpoint's
// implementation.
// udp或tcp伪首部校验和的计算
func (r *Route) PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber) uint16 {
	return header.PseudoHeaderChecksum(protocol, r.LocalAddress, r.RemoteAddress)
}

// Capabilities returns the link-layer capabilities of the route.
func (r *Route) Capabilities() LinkEndpointCapabilities {
	return r.ref.ep.Capabilities()
}

// Resolve 如有必要，解决尝试解析链接地址的问题。如果地址解析需要阻塞，则返回ErrWouldBlock，
// 例如等待ARP回复。地址解析完成（成功与否）时通知Waker。
// 如果需要地址解析，则返回ErrNoLinkAddress和通知通道，以阻止顶级调用者。
// 地址解析完成后，通道关闭（不管成功与否）。
func (r *Route) Resolve(waker *sleep.Waker) (<-chan struct{}, *tcpip.Error) {
	if !r.IsResolutionRequired() {
		// Nothing to do if there is no cache (which does the resolution on cache miss) or
		// link address is already known.
		return nil, nil
	}

	nextAddr := r.NextHop
	if nextAddr == "" {
		// Local link address is already known.
		if r.RemoteAddress == r.LocalAddress { // 发给自己
			r.RemoteLinkAddress = r.LocalLinkAddress // MAC 就是自己
			return nil, nil
		}
		nextAddr = r.RemoteAddress // 下一跳是远端机
	}

	// 调用地址解析协议来解析IP地址
	linkAddr, ch, err := r.ref.linkCache.GetLinkAddress(r.ref.nic.ID(), nextAddr, r.LocalAddress, r.NetProto, waker)
	if err != nil {
		return ch, err
	}
	r.RemoteLinkAddress = linkAddr
	return nil, nil
}

// RemoveWaker removes a waker that has been added in Resolve().
func (r *Route) RemoveWaker(waker *sleep.Waker) {
	nextAddr := r.NextHop
	if nextAddr == "" {
		nextAddr = r.RemoteAddress
	}
	r.ref.linkCache.RemoveWaker(r.ref.nic.ID(), nextAddr, waker)
}

// IsResolutionRequired returns true if Resolve() must be called to resolve
// the link address before the this route can be written to.
func (r *Route) IsResolutionRequired() bool {
	return r.ref.linkCache != nil && r.RemoteLinkAddress == ""
}

// WritePacket writes the packet through the given route.
func (r *Route) WritePacket(hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	err := r.ref.ep.WritePacket(r, hdr, payload, protocol, ttl)
	if err == tcpip.ErrNoRoute {
		r.Stats().IP.OutgoingPacketErrors.Increment()
	}
	return err
}

// DefaultTTL returns the default TTL of the underlying network endpoint.
func (r *Route) DefaultTTL() uint8 {
	return r.ref.ep.DefaultTTL()
}

// MTU returns the MTU of the underlying network endpoint.
func (r *Route) MTU() uint32 {
	return r.ref.ep.MTU()
}

// Release frees all resources associated with the route.
func (r *Route) Release() {
	if r.ref != nil {
		r.ref.decRef()
		r.ref = nil
	}
}

// Clone Clone a route such that the original one can be released and the new
// one will remain valid.
func (r *Route) Clone() Route {
	r.ref.incRef()
	return *r
}
