package stack

import (
	"log"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/ports"
	"netstack/waiter"
	"sync"
	"time"
)

const (
	// ageLimit is set to the same cache stale time used in Linux.
	ageLimit = 1 * time.Minute
	// resolutionTimeout is set to the same ARP timeout used in Linux.
	resolutionTimeout = 1 * time.Second
	// resolutionAttempts is set to the same ARP retries used in Linux.
	resolutionAttempts = 3
)

// TODO 需要解读
type TCPProbeFunc func(s TcpEndpointState)

// TODO 需要解读
type TcpEndpointState struct {
	// TODO 需要添加
}

// 传输层协议状态机 包含传输层协议以及默认处理方法
type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.VectorisedView) bool
}

// Stack 是一个网络堆栈，具有所有支持的协议、NIC 和路由表。
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState // 各种传输层协议
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol           // 各种网络层协议
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver       // 各种链接解析器

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

// Options contains optional Stack configuration.
type Options struct {
	// Clock is an optional clock source used for timestampping packets.
	//
	// If no Clock is specified, the clock source will be time.Now.
	Clock tcpip.Clock

	// Stats are optional statistic counters.
	Stats tcpip.Stats
}

func New(network []string, transport []string, opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = &tcpip.StdClock{}
	}

	s := &Stack{
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		linkAddrResolvers:  make(map[tcpip.NetworkProtocolNumber]LinkAddressResolver),
		nics:               make(map[tcpip.NICID]*NIC),
		linkAddrCache:      newLinkAddrCache(ageLimit, resolutionTimeout, resolutionAttempts),
		PortManager:        ports.NewPortManager(),
		clock:              clock,
		stats:              opts.Stats.FillIn(),
	}

	// 添加指定的网络端协议 必须已经在init中注册过
	for _, name := range network {
		// 先检查这个网络协议是否注册过工厂方法
		netProtoFactory, ok := networkProtocols[name]
		if !ok {
			continue // 没有就略过
		}
		netProto := netProtoFactory()                    // 制造一个该型号协议的示实例
		s.networkProtocols[netProto.Number()] = netProto // 注册该型号的网络协议
	}

	// 添加指定的传输层协议 必已经在init中注册过
	for _, name := range transport {
		transProtoFactory, ok := transportProtocols[name]
		if !ok {
			continue
		}
		transProto := transProtoFactory() // 新建一个传输层协议
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}
	// TODO 添加传输层分流器
	return s
}

func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetForwarding enables or disables the packet forwarding between NICs.
func (s *Stack) SetForwarding(enable bool) {
	// TODO: Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.Lock()
	s.forwarding = enable
	s.mu.Unlock()
}

// Forwarding returns if the packet forwarding between NICs is enabled.
func (s *Stack) Forwarding() bool {
	// TODO: Expose via /proc/sys/net/ipv4/ip_forward.
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwarding
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.routeTable = table
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tcpip.Route(nil), s.routeTable...)
}

// NewEndpoint 根据给定的网络层协议号和传输层协议号新建一个传输层实现
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber,
	network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}
	return t.proto.NewEndpoint(s, network, waiterQueue) // 新建一个传输层实现
}

// CreateNIC 根据给定的网卡号 和 链路层设备号 创建一个网卡对象
func (s *Stack) CreateNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, "", linkEP, true)
}

// CreateNamedNIC creates a NIC with the provided id and link-layer endpoint,
// and a human-readable name.
func (s *Stack) CreateNamedNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, true)
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

// AddSubnet adds a subnet range to the specified NIC.
func (s *Stack) AddSubnet(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.AddSubnet(protocol, subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// RemoveSubnet removes the subnet range from the specified NIC.
func (s *Stack) RemoveSubnet(id tcpip.NICID, subnet tcpip.Subnet) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		nic.RemoveSubnet(subnet)
		return nil
	}

	return tcpip.ErrUnknownNICID
}

// ContainsSubnet reports whether the specified NIC contains the specified
// subnet.
func (s *Stack) ContainsSubnet(id tcpip.NICID, subnet tcpip.Subnet) (bool, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.ContainsSubnet(subnet), nil
	}

	return false, tcpip.ErrUnknownNICID
}

// 路由查找实现，比如当tcp建立连接时，会用该函数得到路由信息
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address,
	netProto tcpip.NetworkProtocolNumber) (Route, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.routeTable {
		if (id != 0 && id != s.routeTable[i].NIC) ||
			(len(remoteAddr) != 0 && !s.routeTable[i].Match(remoteAddr)) {
			continue
		}

		nic := s.nics[s.routeTable[i].NIC]
		if nic == nil {
			continue
		}

		var ref *referencedNetworkEndpoint
		if len(localAddr) != 0 {
			ref = nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
		} else {
			ref = nic.primaryEndpoint(netProto)
		}
		if ref == nil {
			continue
		}

		if len(remoteAddr) == 0 {
			// If no remote address was provided, then the route
			// provided will refer to the link local address.
			remoteAddr = ref.ep.ID().LocalAddress // 发回自己? TODO
		}

		r := makeRoute(netProto, ref.ep.ID().LocalAddress, remoteAddr, nic.linkEP.LinkAddress(), ref)
		r.NextHop = s.routeTable[i].Gateway
		log.Println(r.LocalLinkAddress, r.LocalAddress, r.RemoteLinkAddress, r.RemoteAddress, r.NextHop)
		return r, nil
	}

	return Route{}, tcpip.ErrNoRoute
}

// ===============本机链路层缓存实现==================

// CheckLocalAddress 检查本地是否绑定过该网络层地址 注意 NICID 为0表示寻找本机所有网卡
func (s *Stack) CheckLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicid != 0 {
		nic := s.nics[nicid] // 先拿到网卡
		if nic == nil {
			return 0
		}

		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint) // 看看这张网卡是否绑定过这个地址
		if ref == nil {
			return 0
		}

		ref.decRef() // 这个网络端实现使用结束 释放对它的占用

		return nic.id
	}
	// Go through all the NICs.
	for _, nic := range s.nics {
		ref := nic.findEndpoint(protocol, addr, CanBePrimaryEndpoint)
		if ref != nil {
			ref.decRef()
			return nic.id
		}
	}
	return 0
}

func (s *Stack) AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress) {
	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
	s.linkAddrCache.add(fullAddr, linkAddr)
}

func (s *Stack) GetLinkAddress(nicid tcpip.NICID, addr, localAddr tcpip.Address,
	protocol tcpip.NetworkProtocolNumber, w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	s.mu.RLock()
	// 获取网卡对象
	nic := s.nics[nicid]
	if nic == nil {
		s.mu.RUnlock()
		return "", nil, tcpip.ErrUnknownNICID
	}
	s.mu.RUnlock()

	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
	// 根据网络层协议号找到对应的地址解析协议
	linkRes := s.linkAddrResolvers[protocol]
	return s.linkAddrCache.get(fullAddr, linkRes, localAddr, nic.linkEP, w)
}

func (s *Stack) RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic := s.nics[nicid]; nic == nil {
		fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr}
		s.linkAddrCache.removeWaker(fullAddr, waker)
	}
}

// RegisterTransportEndpoint 协议栈或者NIC的分流器注册给定传输层端点。
// 收到的与提供的id匹配的数据包将被传送到给定的端点;指定nic是可选的，但特定于nic的ID优先于全局ID。
// 最终调用 demuxer.registerEndpoint 函数来实现注册。
func (s *Stack) RegisterTransportEndpoint(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	// TODO 需要实现
	return nil
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {

}

// NetworkProtocolInstance returns the protocol instance in the stack for the
// specified network protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

// TransportProtocolInstance returns the protocol instance in the stack for the
// specified transport protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}
