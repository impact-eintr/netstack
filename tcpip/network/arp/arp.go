// 主机的链路层寻址是通过 arp 表来实现的
package arp

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
)

const (
	ProtocolName    = "arp"
	ProtocolNumber  = header.ARPProtocolNumber
	ProtocolAddress = tcpip.Address("arp")
)

// arp endpoint 一个网络层的实现 Implement stack.NetworkEndpoint
type endpoint struct {
	nicid         tcpip.NICID            // arp报文使用的网卡
	addr          tcpip.Address          // 网络层地址
	linkEP        stack.LinkEndpoint     // MAC
	linkAddrCache stack.LinkAddressCache // 链路高速缓存
}

func (e *endpoint) DefaultTTL() uint8 {
	return 0
}

func (e *endpoint) MTU() uint32 {
	lmtu := e.linkEP.MTU()
	return lmtu - uint32(e.MaxHeaderLength())
}

func (e *endpoint) NICID() tcpip.NICID {
	return e.nicid
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &stack.NetworkEndpointID{LocalAddress: ProtocolAddress}
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.ARPSize
}

// arp不支持写包
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// arp数据包的处理，包括arp请求和响应
func (e *endpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
	v := vv.First()
	h := header.ARP(v)
	if !h.IsValid() {
		return
	}

	// 判断操作码类型
	switch h.Op() {
	case header.ARPRequest:
		// 如果是ARP请求
		localAddr := tcpip.Address(h.ProtocolAddressTarget())
		if e.linkAddrCache.CheckLocalAddress(e.nicid, header.IPv4ProtocolNumber, localAddr) == 0 {
			return // 无效的ARP请求
		}

		// arp报文所在的网卡绑定了这个地址
		hdr := buffer.NewPrependable(int(e.linkEP.MaxHeaderLength()) + header.ARPSize) // 以太 + ARP
		pkt := header.ARP(hdr.Prepend(header.ARPSize))                                 //  取出 ARP
		pkt.SetIPv4OverEthernet()
		pkt.SetOp(header.ARPReply)
		copy(pkt.HardwareAddressSender(), r.LocalLinkAddress[:]) // 写入本机MAC作为响应 NOTE
		// 倒置目标与源 作为回应
		copy(pkt.ProtocolAddressSender(), h.ProtocolAddressTarget())
		copy(pkt.ProtocolAddressTarget(), h.ProtocolAddressSender())
		log.Println("处理注入的ARP请求 这里将返回一个ARP报文作为响应", tcpip.LinkAddress(pkt.HardwareAddressTarget()))
		e.linkEP.WritePacket(r, hdr, buffer.VectorisedView{}, ProtocolNumber) // 往链路层写回消息
		// 注意这里的 fallthrough 表示需要继续执行下面分支的代码
		// 当收到 arp 请求需要添加到链路地址缓存中
		fallthrough // also fill the cache from requests
	case header.ARPReply:
		// 这里记录ip和mac对应关系，也就是arp表
		addr := tcpip.Address(h.ProtocolAddressSender())
		linkAddr := tcpip.LinkAddress(h.HardwareAddressSender()) // 记录远端机的MAC地址
		e.linkAddrCache.AddLinkAddress(e.nicid, addr, linkAddr)
	default:
		panic(tcpip.ErrUnknownProtocol)
	}
}

func (e *endpoint) Close() {}

// 实现了 stack.NetworkProtocol 和 stack.LinkAddressResolver 两个接口
type protocol struct{}

func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache,
	dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	if addr != ProtocolAddress {
		return nil, tcpip.ErrBadLocalAddress
	}
	return &endpoint{
		nicid:         nicid,
		addr:          addr,
		linkEP:        linkEP,
		linkAddrCache: linkAddrCache,
	}, nil
}

func (p *protocol) MinimumPacketSize() int {
	return header.ARPSize
}

func (p *protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.ARP(v)
	return tcpip.Address(h.ProtocolAddressSender()), ProtocolAddress
}

func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// LinkAddressProtocol implements stack.LinkAddressResolver.
func (*protocol) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return header.IPv4ProtocolNumber
}

// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, linkEP stack.LinkEndpoint) *tcpip.Error {
	r := &stack.Route{
		RemoteLinkAddress: broadcastMAC,
	}

	hdr := buffer.NewPrependable(int(linkEP.MaxHeaderLength()) + header.ARPSize)
	h := header.ARP(hdr.Prepend(header.ARPSize))
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), linkEP.LinkAddress())
	copy(h.ProtocolAddressSender(), localAddr)
	copy(h.ProtocolAddressTarget(), addr)
	log.Println("arp发起广播 寻找:", addr, r)
	return linkEP.WritePacket(r, hdr, buffer.VectorisedView{}, ProtocolNumber)
}

// ResolveStaticAddress implements stack.LinkAddressResolver.
func (*protocol) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == "\xff\xff\xff\xff" {
		return broadcastMAC, true
	}
	return "", false
}

var broadcastMAC = tcpip.LinkAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

func init() {
	stack.RegisterNetworkProtocolFactory(ProtocolName, func() stack.NetworkProtocol {
		return &protocol{}
	})
}
