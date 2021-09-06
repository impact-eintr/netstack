package stack

import (
	"sync"

	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
	"github.com/impact-eintr/netstack/tcpip/ports"
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.VectorisedView) bool
}

type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver

	demux *transportDemuxer

	stats tcpip.Stats

	linkAddrCache *linkAddrCache

	mu         sync.RWMutex
	nics       map[tcpip.NICID]*NIC
	forwarding bool

	routeTable []tcpip.Route

	*ports.PortManager
	tcpProbeFunc TCPProbeFunc
	clock        tcpip.Clock
}

type Options struct {
	Clock tcpip.Clock
	Stats tcpip.Stats
}

// TCPProbeFunc 是要传递给 stack.AddTCPProbe 的 TCP 探测函数的预期函数类型
type TCPProbeFunc func(s TCPEndpointState)

// TCPEndpointState 是 TCP 端点内部状态的副本
type TCPEndpointState struct {
}
