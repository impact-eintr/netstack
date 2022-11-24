package stack

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/ports"
	"sync"
)

// TODO 需要解读
type TCPProbeFunc func(s TcpEndpointState)

// TODO 需要解读
type TcpEndpointState struct {
	// TODO 需要添加
}

type transportProtocolState struct {
}

// Stack 是一个网络堆栈，具有所有支持的协议、NIC 和路由表。
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState // 各种传输层协议
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol           // 各种网络层协议
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver       // 各种传输层协议

	demux *transportDemuxer // 传输层的复用器

	stats tcpip.Stats // 网络栈的状态监测器

	linkAddrCache *linkAddrCache // 链路层地址的缓存

	mu         sync.RWMutex
	nics       map[tcpip.NICID]*NIC // 所有的网卡设备
	forwarding bool                 // 是否正在转发

	// route is the route table passed in by the user via SetRouteTable(),
	// it is used by FindRoute() to build a route for a specific
	// destination.
	routeTable []tcpip.Route // 路由表

	*ports.PortManager // 端口管理器

	// If not nil, then any new endpoints will have this probe function
	// invoked everytime they receive a TCP segment.
	tcpProbeFunc TCPProbeFunc

	// clock is used to generate user-visible times.
	clock tcpip.Clock
}

func New(network []string) *Stack {
	s := &Stack{
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		linkAddrResolvers:  make(map[tcpip.NetworkProtocolNumber]LinkAddressResolver),
		nics:               make(map[tcpip.NICID]*NIC),
	}

	// 添加指定的网络端协议 必须已经在init中注册过
	for _, name := range network {
		// 先检查这个网络协议是否注册过工厂方法
		netProtoFactory, ok := networkProtocols[name]
		if !ok {
			log.Println(name)
			continue // 没有就略过
		}
		netProto := netProtoFactory()                    // 制造一个该型号协议的示实例
		s.networkProtocols[netProto.Number()] = netProto // 注册该型号的网络协议
	}

	// 添加指定的传输层协议 必已经在init中注册过
	// TODO
	return s
}

func (s *Stack) CreateNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, "", linkEP, true)
}

// 新建一个网卡对象，并且激活它 激活就是准备好熊网卡中读取和写入数据
func (s *Stack) createNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID, enable bool) *tcpip.Error {
	ep := FindLinkEndpoint(linkEP)
	if ep == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique
	if _, ok := s.nics[id]; ok {
		return tcpip.ErrDuplicateNICID
	}
	n := newNIC(s, id, name, ep)

	s.nics[id] = n
	if enable {
		n.attachLinkEndpoint()
	}

	return nil
}

// 给网卡添加ip地址
func (s *Stack) AddAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) *tcpip.Error {
	return s.AddAddressWithOptions(id, protocol, addr, CanBePrimaryEndpoint)
}

func (s *Stack) AddAddressWithOptions(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber,
	addr tcpip.Address, peb PrimaryEndpointBehavior) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.AddAddressWithOptions(protocol, addr, peb)
}
