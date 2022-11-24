package stack

import (
	"log"
	"netstack/ilist"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"sync"
)

const (
	CapabilityChecksumOffload LinkEndpointCapabilities = 1 << iota
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOK
	CapabilityLoopback
)

// ====================链路层相关==============================

// 所谓 io 就是数据的输入输出，对于网卡来说就是接收或发送数据，
// 接收意味着对以太网帧解封装和提交给网络层，发送意味着对上层数据的封装和写入网卡

// 链路层接口
type LinkEndpoint interface {
	// MTU是此端点的最大传输单位。这通常由支持物理网络决定;
	// 当这种物理网络不存在时，限制通常为64k，其中包括IP数据包的最大大小。
	MTU() uint32

	// Capabilities返回链路层端点支持的功能集。
	Capabilities() LinkEndpointCapabilities

	// MaxHeaderLength 返回数据链接（和较低级别的图层组合）标头可以具有的最大大小。
	// 较高级别使用此信息来保留它们正在构建的数据包前面预留空间。
	MaxHeaderLength() uint16

	// 本地链路层地址
	LinkAddress() tcpip.LinkAddress

	// 要参与透明桥接，LinkEndpoint实现应调用eth.Encode，
	// 并将header.EthernetFields.SrcAddr设置为r.LocalLinkAddress（如果已提供）。
	WritePacket(r *Route, hdr buffer.Prependable, payload buffer.VectorisedView,
		protocol tcpip.NetworkProtocolNumber) *tcpip.Error

	// Attach 将数据链路层端点附加到协议栈的网络层调度程序。
	Attach(dispatcher NetworkDispatcher)

	// 是否已经添加了网络层调度器
	IsAttached() bool
}

// LinkAddressResolver 是对可以解析链接地址的 NetworkProtocol 的扩展 TODO 需要解读
type LinkAddressResolver interface {
	LinkAddressRequest(addr, localAddr tcpip.Address, linkEP LinkEndpoint) *tcpip.Error

	ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool)

	LinkAddressProtocol() tcpip.NetworkProtocolNumber
}

// A LinkAddressCache caches link addresses.
type LinkAddressCache interface {
	// CheckLocalAddress determines if the given local address exists, and if it
	// does not exist.
	CheckLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID

	// AddLinkAddress adds a link address to the cache.
	AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)

	// GetLinkAddress looks up the cache to translate address to link address (e.g. IP -> MAC).
	// If the LinkEndpoint requests address resolution and there is a LinkAddressResolver
	// registered with the network protocol, the cache attempts to resolve the address
	// and returns ErrWouldBlock. Waker is notified when address resolution is
	// complete (success or not).
	//
	// If address resolution is required, ErrNoLinkAddress and a notification channel is
	// returned for the top level caller to block. Channel is closed once address resolution
	// is complete (success or not).
	GetLinkAddress(nicid tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber, w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error)

	// RemoveWaker removes a waker that has been added in GetLinkAddress().
	RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker)
}

type NetworkDispatcher interface {
	DeliverNetworkPacket(linkEP LinkEndpoint, dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
		protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView)
}

type LinkEndpointCapabilities uint

// type TransportProtocolFactory func() TransportProtocol TODO

type NetworkProtocolFactory func() NetworkProtocol

var (
	// 以下两个map需要在init函数中注册
	// 传输层协议的注册存储结构 TODO
	//transportProtocols = make(map[string]TransportProtocolFactory)
	// 网络层协议的注册存储结构
	networkProtocols = make(map[string]NetworkProtocolFactory)

	linkEPMu           sync.RWMutex
	nextLinkEndpointID tcpip.LinkEndpointID = 1
	linkEndpoints                           = make(map[tcpip.LinkEndpointID]LinkEndpoint) // 设备注册表 设备号:设备实现
)

// ==============================网络层相关==============================
type NetworkProtocol interface {
	Number() tcpip.NetworkProtocolNumber
	// todo 需要添加
}

// NetworkEndpoint是需要由网络层协议（例如，ipv4，ipv6）的端点实现的接口
type NetworkEndpoint interface {
	// TODO 需要添加
}

type NetworkEndpointID struct {
	LocalAddress tcpip.Address
}

// ==============================传输层相关==============================

type TransportEndpointID struct {
	// TODO
}

// ControlType 是网络层控制消息的类型
type ControlType int

// TODO 需要解读
type TransportEndpoint interface {
	HandlePacket(r *Route, id TransportEndpointID, vv buffer.VectorisedView)
	HandleControlPacker(id TransportEndpointID, typ ControlType, extra uint32, vv buffer.VectorisedView)
}

// TODO 需要解读
type referencedNetworkEndpoint struct {
	ilist.Entry
	refs     int32
	ep       NetworkEndpoint
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

// 注册一个新的网络协议工厂
func RegisterNetworkProtocolFactory(name string, p NetworkProtocolFactory) {
	networkProtocols[name] = p
	log.Println(networkProtocols)
}

// 注册一个链路层设备
func RegisterLinkEndpoint(linkEP LinkEndpoint) tcpip.LinkEndpointID {
	linkEPMu.Lock()
	defer linkEPMu.Unlock()

	v := nextLinkEndpointID
	nextLinkEndpointID++

	linkEndpoints[v] = linkEP

	return v
}

func FindLinkEndpoint(id tcpip.LinkEndpointID) LinkEndpoint {
	linkEPMu.RLock()
	defer linkEPMu.RUnlock()

	return linkEndpoints[id]
}
