package stack

import (
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
	Atach(dispatcher NetworkDispatcher)

	// 是否已经添加了网络调度器
	IsAttached() bool
}

type LinkEndpointCapabilities uint

const (
	CapabilityChecksumOffload LinkEndpointCapabilities = 1 << iota
	CapabilityResolutionRequired
	CapabilitySaveRestore
	CapabilityDisconnectOk
	CapabilityLoopback
)

type NetworkDispatcher interface {
}
