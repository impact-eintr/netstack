package stack

import "github.com/impact-eintr/netstack/tcpip"

// 贯穿整个协议栈的路由，也就是在链路层和网络层都可以路由
// 如果目标地址是链路层地址，那么在链路层路由
// 如果目标地址是网络层地址，那么在网络层路由
type Route struct {
	// 远端网络层地址 ipv4 or ipv6
	RemoteAddress tcpip.Address

	// 远端网卡MAC地址
	RemoteLinkAddress tcpip.LinkAddress

	// 本地网络层地址
	LocalAddress tcpip.Address

	// 本地网卡MAC地址
	LocalLinkAddress tcpip.LinkAddress

	// 下一跳网络层地址
	NextHop tcpip.Address

	// 网络层协议号
	NextProto tcpip.NetworkProtocolNumber

	// 相关的网络终端
	ref *referencedNetworkEndpoint
}
