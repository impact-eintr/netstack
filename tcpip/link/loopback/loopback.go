package loopback

import (
	"fmt"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/stack"
)

type endpoint struct {
	count      int
	dispatcher stack.NetworkDispatcher
}

func New() tcpip.LinkEndpointID {
	return stack.RegisterLinkEndpoint(&endpoint{})
}

func (e *endpoint) MTU() uint32 {
	return 65536
}

// Capabilities返回链路层端点支持的功能集。
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityLoopback
}

// MaxHeaderLength 返回数据链接（和较低级别的图层组合）标头可以具有的最大大小。
// 较高级别使用此信息来保留它们正在构建的数据包前面预留空间。
func (e *endpoint) MaxHeaderLength() uint16 {
	return 0
}

// 本地链路层地址
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

// 要参与透明桥接，LinkEndpoint实现应调用eth.Encode，
// 并将header.EthernetFields.SrcAddr设置为r.LocalLinkAddress（如果已提供）。
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	views := make([]buffer.View, 1, 1+len(payload.Views()))
	views[0] = hdr.View()
	views = append(views, payload.Views()...)
	vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views)

	// TODO 这里整点活 在特定的情况下丢掉数据报 模拟网络阻塞

	e.count++
	if e.count == 6 { // 丢掉客户端写入的第二个包
		logger.NOTICE(fmt.Sprintf("统计 %d  丢掉这个报文", e.count))
		return nil
	}
	// Because we're immediately turning around and writing the packet back to the
	// rx path, we intentionally don't preserve the remote and local link
	// addresses from the stack.Route we're passed.
	logger.NOTICE(fmt.Sprintf("统计分发 %d 报文", e.count))
	e.dispatcher.DeliverNetworkPacket(e, "" /* remoteLinkAddr */, "" /* localLinkAddr */, protocol, vv)

	return nil
}

// Attach 将数据链路层端点附加到协议栈的网络层调度程序。
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// 是否已经添加了网络层调度器
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}
