package stack

import (
	"sync"

	"github.com/impact-eintr/netstack/sleep"
	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
)

// LinkEndpoint是由数据链路层协议(以太 环回 原始)实现的接口
// 并由网络层协议用于实施者的数据链路端点发送数据包
type LinkEndpoint interface {
	// MTU通常是这个端点的最大传输单位 这通常由支持物理网络决定
	// 当这种物理网络不存在时 限制通常是64K，其中包括IP数据包的最大大小
	MTU() uint32

	// 返回链路层端点支持的功能集
	Capabilities() LinkEndpointCapabilities

	// 返回数据链接(以及更底层的层次)Header的最大大小
	MaxHeaderLength() uint16

	// 本地链路层地址
	LinkAddress() tcpip.LinkAddress

	// 通过给定的路由写入具有给定协议的数据包
	// 参与透明桥接，LinkEndpoint实现应调用eth.Encode，
	// 并将header.EthernetFields.SrcAddr设置为r.LocalLinkAddress（如果已提供）
	WritePacket(r *Route, hdr buffer.Prependable, payload buffer.VectorisedView,
		protocol tcpip.NetworkProtocolNumber) *tcpip.Error

	// 将数据链路层端点附加到协议栈的为那个网络层调度程序
	Attach(dispatcher NetworkDispatcher)

	// 是否已经添加了网络调度器
	IsAttached() bool
}

type LinkAddressResolver interface {
}

type LinkEndpointCapabilities uint

const (
	CapabilityChecksumOffload LinkEndpointCapabilities = 1 << iota
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOk
	CapabilityLoopback
)

var (
	// 传输层协议的注册存储结构
	//transportProtocols = make(map[string]TransportProtocolFactory)
	// 网络层协议的注册存储结构
	//networkProtocols   = make(map[string]TransportProtocolFactory)
	linkEPMu           sync.RWMutex
	nextLinkEndpointID tcpip.LinkEndpointID = 1
	// 保存设备号与设备信息
	linkEndpoints = make(map[tcpip.LinkEndpointID]LinkEndpoint)
)

// 链路层

// LinkAddressCache 缓存链接地址。
type LinkAddressCache interface {
	// CheckLocalAddress 确定给定的本地地址是否存在
	CahceLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID
	// AddLinkAddress 向缓存添加链接地址
	AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)
	// GetLinkAddress 查找缓存以将地址转换为链接地址（例如 IP -> MAC）。
	// 如果 LinkEndpoint 请求地址解析并且存在使用网络协议注册的 Link Address Resolver，则缓存尝试解析地址并返回 EWouldBlock。
	// 如果需要地址解析，则返回 ErrNoLinkAddress 和通知通道以供顶级调用方阻止。 一旦地址解析完成（成功与否），通道就会关闭。
	GetLinkAddress(nic tcpip.NICID, addr, localAddr tcpip.Address, protocol tcpip.NetworkProtocolNumber,
		w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error)
	// RemoveWaker 移除已在 GetLinkAddress() 中添加的唤醒器。
	RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker)
}

// 注册一个链路层设备
func RegisterLinkEndpoint(linkEP LinkEndpoint) tcpip.LinkEndpointID {
	linkEPMu.Lock()
	defer linkEPMu.Unlock()

	v := nextLinkEndpointID
	nextLinkEndpointID++

	// 进行注册
	linkEndpoints[v] = linkEP
	return v

}

// 根据ID找到网卡设备
func FindLinkEndpoint(id tcpip.LinkEndpointID) LinkEndpoint {
	linkEPMu.RLock()
	defer linkEPMu.RUnlock()
	return linkEndpoints[id]
}

// 网络层

// ControlType 是网络控制消息的类型
type ControlType int

// 以下是 ControlType 值的允许值
const (
	ControlPacketTooBig ControlType = iota
	ControlPortUnreachable
	ControlUnknown
)

// 需要由网络层协议(ipv4 ipv6)的端点实现的接口
type NetworkEndpoint interface {
	// DefaultTTL 是此端点的默认生存时间值（或跳数限制，在 ipv6 中）
	DefaultTTL() uint8
	// MTU 是该端点的最大传输单元。这通常计算为底层数据链路端点的 MTU 减去网络端点最大报头长度
	MTU() uint32
	Capabilities() LinkEndpointCapabilities // 返回底层链路层端点支持的能力集
	// MaxHeaderLength 返回网络（和较低级别的层）标头可以具有的最大大小。
	// 更高层使用此信息在他们正在构建的数据包前面保留空间
	MaxHeaderLength() uint16
	// WritePacket 将数据包写入给定的目标地址和协议
	WritePacket(r *Route, hdr buffer.Prependable, payload buffer.VectorisedView,
		protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error
	ID() *NetworkEndpointID // ID 返回网络协议端点 ID
	NICID() tcpip.NICID

	// 当新数据包到达此网络端点时，链路层会调用 HandlePacket
	HandlePacket(r *Route, hdr buffer.Prependable, payload buffer.VectorisedView,
		protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error
	// 当端点从堆栈中移除时调用 Close
	Close()
}

// NetworkProtocol 是需要由希望成为网络堆栈一部分的网络协议（例如，ipv4、ipv6）实现的接口
type NetworkProtocol interface {
	// Number 返回网络协议号
	Number() tcpip.NetworkProtocolNumber
	// MinimumPacketSize 返回此网络协议的最小有效数据包大小。堆栈会自动丢弃任何小于此协议的数据包
	MinimumPacketSize() int
	// ParsePorts 返回存储在该协议数据包中的源地址和目的地址
	ParseAddresses(v buffer.View) (src, dst tcpip.Address)
	// NewEndpoint 创建此协议的新端点。
	NewEndpoint(cicid tcpip.NICID, addr tcpip.Address, linkAddrCache LinkAddressCache,
		dispatcher TransportDispatcher, sender LinkEndpoint) (NetworkEndpoint, *tcpip.Error)
	// SetOption 允许启用/禁用协议特定功能。
	// 如果不支持该选项或提供的选项值无效，则 SetOption 将返回错误。
	SetOption(option interface{}) *tcpip.Error
	// Option 允许检索协议特定的选项值。 如果选项不受支持或提供的选项值无效，则Option 返回错误。
	Option(option interface{}) *tcpip.Error
}

// 包含网络协议栈用于在 数据链路层 处理数据包后将数据包传送到适当网络端点的方法。
type NetworkDispatcher interface {
	// deliver 递送
	DeliverNetworkPacket(linkEP LinkEndpoint, dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
		protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView)
}

// 传输层

type TransportEndpointID struct {
	LocalPort     uint16
	LocalAddress  tcpip.Address
	RemotePort    uint16
	RemoteAddress tcpip.Address
}

// TransportProtocol 是需要由希望成为网络堆栈一部分的传输协议（例如，tcp、udp）实现的接口
type TransportProtocol interface {
	// Number 返回传输协议号
	Number() tcpip.TransportProtocolNumber
	// MinimumPacketSize 返回此网络协议的最小有效数据包大小。堆栈会自动丢弃任何小于此协议的数据包
	MinimumPacketSize() int
	// ParsePorts 返回存储在该协议数据包中的源端口和目的端口
	ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error)
	// HandleUnknownDestinationPacket 处理以该协议为目标但不匹配任何现有端点的数据包。
	// 例如，它针对没有侦听器的端口
	HandleUnknowDestinationPacket(r *Route, id TransportEndpointID, vv buffer.VectorisedView) bool

	// SetOption 允许启用/禁用协议特定功能。
	// 如果不支持该选项或提供的选项值无效，则 SetOption 将返回错误。
	SetOption(option interface{}) *tcpip.Error
	// Option 允许检索协议特定的选项值。 如果选项不受支持或提供的选项值无效，则Option 返回错误。
	Option(option interface{}) *tcpip.Error
}

// TransportDispatcher 包含网络堆栈用于在 网络层 处理数据包后将数据包传送到适当的传输端点的方法
type TransportDispatcher interface {
	// DeliverTransportPacket 将数据包传送到适当的传输协议端点。
	DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView)
	// DeliverTransportControlPacket 将控制数据包传送到适当的传输协议端点。
	DeliverTransportControlPacket(local, remote tcpip.Address, net tcpip.NetworkProtocolNumber,
		trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView)
}
