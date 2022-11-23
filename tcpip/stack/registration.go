package stack

import (
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


type NetworkDispatcher interface {
	DeliverNetworkPacket(linkEP LinkEndpoint, dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
		protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView)
}

type LinkEndpointCapabilities uint


var (
	// 传输层协议的注册存储结构 TODO
	// 网络层协议的注册存储结构 TODO

	linkEPMu sync.RWMutex
	nextLinkEndpointID tcpip.LinkEndpointID = 1
	linkEndpoints = make(map[tcpip.LinkEndpointID]LinkEndpoint) // 设备注册表 设备号:设备实现
)

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
