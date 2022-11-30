package channel

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/stack"
)

type PacketInfo struct {
	Header  buffer.View
	Payload buffer.View
	Proto   tcpip.NetworkProtocolNumber
}

type Endpoint struct {
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	linkAddr   tcpip.LinkAddress // MAC地址
	C          chan PacketInfo
}

//创建一个新的抽象cahnnel Endpoint 可以接受数据 也可以外发数据
func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) (tcpip.LinkEndpointID, *Endpoint) {
	e := &Endpoint{
		C:        make(chan PacketInfo, size),
		mtu:      mtu,
		linkAddr: linkAddr,
	}
	return stack.RegisterLinkEndpoint(e), e
}

// Drain 流走 释放channel中的数据
func (e *Endpoint) Drain() int {
	c := 0
	for {
		select {
		case <-e.C:
			c++
		default:
			return c
		}
	}
}

// Inject 注入
func (e *Endpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	e.InjectLinkAddr(protocol, "", vv)
}

// InjectLinkAddr injects an inbound packet with a remote link address.
func (e *Endpoint) InjectLinkAddr(protocol tcpip.NetworkProtocolNumber, remoteLinkAddr tcpip.LinkAddress, vv buffer.VectorisedView) {
	// 这里的实现在NIC.go中 由 网卡对象进行数据分发
	e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, "" /* localLinkAddr */, protocol, vv.Clone(nil))
}

func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities返回链路层端点支持的功能集。
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

// MaxHeaderLength 返回数据链接（和较低级别的图层组合）标头可以具有的最大大小。
// 较高级别使用此信息来保留它们正在构建的数据包前面预留空间。
func (e *Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// 本地链路层地址
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// channel 向外写数据
func (e *Endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	p := PacketInfo{
		Header:  hdr.View(),
		Proto:   protocol,
		Payload: payload.ToView(),
	}

	select {
	case e.C <- p:
	default:
	}

	return nil
}

// Attach 将数据链路层端点附加到协议栈的网络层调度程序。
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// 是否已经添加了网络层调度器
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}
