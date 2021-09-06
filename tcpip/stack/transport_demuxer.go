package stack

import (
	"sync"

	"github.com/impact-eintr/netstack/tcpip"
)

// 解复用针对传输端点的数据包 在他们被网络层解析之后
// 它执行两级解复用 首先基于网络协议和传输协议 然后基于端点ID
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}

// 管理给定协议的所有端点
type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]*transportEndpoints
}

// 网络层协议号和传输层协议号的组合 当作分流器的key值
type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}
