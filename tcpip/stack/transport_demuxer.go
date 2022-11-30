package stack

import (
	"netstack/tcpip"
	"sync"
)

// 网络层协议号和传输层协议号的组合 当作分流器的key值
type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
}

// transportDemuxer 解复用战队传输端点的数据包
// 他执行两级解复用：首先基于网络层和传输协议 然后基于端点ID
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}
