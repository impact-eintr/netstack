package stack

import (
	"log"
	"netstack/logger"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/ports"
	"netstack/tcpip/seqnum"
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

// TCPProbeFunc is the expected function type for a TCP probe function to be
// passed to stack.AddTCPProbe.
type TCPProbeFunc func(s TCPEndpointState)

// TCPCubicState is used to hold a copy of the internal cubic state when the
// TCPProbeFunc is invoked.
type TCPCubicState struct {
	WLastMax                float64
	WMax                    float64
	T                       time.Time
	TimeSinceLastCongestion time.Duration
	C                       float64
	K                       float64
	Beta                    float64
	WC                      float64
	WEst                    float64
}

// 传输层协议状态机 包含传输层协议以及默认处理方法
type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.VectorisedView) bool
}

// TCPEndpointID is the unique 4 tuple that identifies a given endpoint.
type TCPEndpointID struct {
	// LocalPort is the local port associated with the endpoint.
	LocalPort uint16

	// LocalAddress is the local [network layer] address associated with
	// the endpoint.
	LocalAddress tcpip.Address

	// RemotePort is the remote port associated with the endpoint.
	RemotePort uint16

	// RemoteAddress it the remote [network layer] address associated with
	// the endpoint.
	RemoteAddress tcpip.Address
}

// TCPFastRecoveryState holds a copy of the internal fast recovery state of a
// TCP endpoint.
type TCPFastRecoveryState struct {
	// Active if true indicates the endpoint is in fast recovery.
	Active bool

	// First is the first unacknowledged sequence number being recovered.
	First seqnum.Value

	// Last is the 'recover' sequence number that indicates the point at
	// which we should exit recovery barring any timeouts etc.
	Last seqnum.Value

	// MaxCwnd is the maximum value we are permitted to grow the congestion
	// window during recovery. This is set at the time we enter recovery.
	MaxCwnd int
}

// TCPReceiverState holds a copy of the internal state of the receiver for
// a given TCP endpoint.
type TCPReceiverState struct {
	// RcvNxt is the TCP variable RCV.NXT.
	RcvNxt seqnum.Value

	// RcvAcc is the TCP variable RCV.ACC.
	RcvAcc seqnum.Value

	// RcvWndScale is the window scaling to use for inbound segments.
	RcvWndScale uint8

	// PendingBufUsed is the number of bytes pending in the receive
	// queue.
	PendingBufUsed seqnum.Size

	// PendingBufSize is the size of the socket receive buffer.
	PendingBufSize seqnum.Size
}

// TCPSenderState holds a copy of the internal state of the sender for
// a given TCP Endpoint.
type TCPSenderState struct {
	// LastSendTime is the time at which we sent the last segment.
	LastSendTime time.Time

	// DupAckCount is the number of Duplicate ACK's received.
	DupAckCount int

	// SndCwnd is the size of the sending congestion window in packets.
	SndCwnd int

	// Ssthresh is the slow start threshold in packets.
	Ssthresh int

	// SndCAAckCount is the number of packets consumed in congestion
	// avoidance mode.
	SndCAAckCount int

	// Outstanding is the number of packets in flight.
	Outstanding int

	// SndWnd is the send window size in bytes.
	SndWnd seqnum.Size

	// SndUna is the next unacknowledged sequence number.
	SndUna seqnum.Value

	// SndNxt is the sequence number of the next segment to be sent.
	SndNxt seqnum.Value

	// RTTMeasureSeqNum is the sequence number being used for the latest RTT
	// measurement.
	RTTMeasureSeqNum seqnum.Value

	// RTTMeasureTime is the time when the RTTMeasureSeqNum was sent.
	RTTMeasureTime time.Time

	// Closed indicates that the caller has closed the endpoint for sending.
	Closed bool

	// SRTT is the smoothed round-trip time as defined in section 2 of
	// RFC 6298.
	SRTT time.Duration

	// RTO is the retransmit timeout as defined in section of 2 of RFC 6298.
	RTO time.Duration

	// RTTVar is the round-trip time variation as defined in section 2 of
	// RFC 6298.
	RTTVar time.Duration

	// SRTTInited if true indicates take a valid RTT measurement has been
	// completed.
	SRTTInited bool

	// MaxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	MaxPayloadSize int

	// SndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	SndWndScale uint8

	// MaxSentAck is the highest acknowledgement number sent till now.
	MaxSentAck seqnum.Value

	// FastRecovery holds the fast recovery state for the endpoint.
	FastRecovery TCPFastRecoveryState

	// Cubic holds the state related to CUBIC congestion control.
	Cubic TCPCubicState
}

// TCPSACKInfo holds TCP SACK related information for a given TCP endpoint.
type TCPSACKInfo struct {
	// Blocks is the list of SACK block currently received by the
	// TCP endpoint.
	Blocks []header.SACKBlock
}

// TCPEndpointState is a copy of the internal state of a TCP endpoint.
type TCPEndpointState struct {
	// ID is a copy of the TransportEndpointID for the endpoint.
	ID TCPEndpointID

	// SegTime denotes the absolute time when this segment was received.
	SegTime time.Time

	// RcvBufSize is the size of the receive socket buffer for the endpoint.
	RcvBufSize int

	// RcvBufUsed is the amount of bytes actually held in the receive socket
	// buffer for the endpoint.
	RcvBufUsed int

	// RcvClosed if true, indicates the endpoint has been closed for reading.
	RcvClosed bool

	// SendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1.
	SendTSOk bool

	// RecentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	RecentTS uint32

	// TSOffset is a randomized offset added to the value of the TSVal field
	// in the timestamp option.
	TSOffset uint32

	// SACKPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	SACKPermitted bool

	// SACK holds TCP SACK related information for this endpoint.
	SACK TCPSACKInfo

	// SndBufSize is the size of the socket send buffer.
	SndBufSize int

	// SndBufUsed is the number of bytes held in the socket send buffer.
	SndBufUsed int

	// SndClosed indicates that the endpoint has been closed for sends.
	SndClosed bool

	// SndBufInQueue is the number of bytes in the send queue.
	SndBufInQueue seqnum.Size

	// PacketTooBigCount is used to notify the main protocol routine how
	// many times a "packet too big" control packet is received.
	PacketTooBigCount int

	// SndMTU is the smallest MTU seen in the control packets received.
	SndMTU int

	// Receiver holds variables related to the TCP receiver for the endpoint.
	Receiver TCPReceiverState

	// Sender holds state related to the TCP Sender for the endpoint.
	Sender TCPSenderState
}

// Stack 是一个网络堆栈，具有所有支持的协议、NIC 和路由表。
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState // 各种传输层协议
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol           // 各种网络层协议
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver       // 支持链接层反向解析的网络层协议

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

// New 新建一个网络协议栈
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
		// 判断该协议是否支持链路层地址解析协议接口，如果支持添加到 s.linkAddrResolvers 中，
		// 如：ARP协议会添加 IPV4-ARP 的对应关系
		// 后面需要地址解析协议的时候会更改网络层协议号来找到相应的地址解析协议
		if r, ok := netProto.(LinkAddressResolver); ok {
			s.linkAddrResolvers[r.LinkAddressProtocol()] = r // 其实就是说： 声明arp支持地址解析
		}
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
	// NOTE 添加协议栈全局传输层分流器
	s.demux = newTransportDemuxer(s)

	return s
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.SetOption(option)
}

// NetworkProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// e.g.
// var v ipv4.MyOption
// err := s.NetworkProtocolOption(tcpip.IPv4ProtocolNumber, &v)
//
//	if err != nil {
//	  ...
//	}
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option interface{}) *tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.SetOption(option)
}

// TransportProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
// var v tcp.SACKEnabled
//
//	if err := s.TransportProtocolOption(tcpip.TCPProtocolNumber, &v); err != nil {
//	  ...
//	}
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option interface{}) *tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return tcpip.ErrUnknownProtocol
	}
	return transProtoState.proto.Option(option)
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(*Route, TransportEndpointID, buffer.VectorisedView) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (s *Stack) NowNanoseconds() int64 {
	return s.clock.NowNanoseconds()
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

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) *tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.RemoveAddress(addr)
	}

	return tcpip.ErrUnknownNICID
}

// FindRoute 路由查找实现，比如当tcp建立连接时，会用该函数得到路由信息
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address,
	netProto tcpip.NetworkProtocolNumber) (Route, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.routeTable {
		if (id != 0 && id != s.routeTable[i].NIC) || // 检查是否是对应的网卡
			(len(remoteAddr) != 0 && !s.routeTable[i].Match(remoteAddr)) {
			continue
		}

		nic := s.nics[s.routeTable[i].NIC] // 在协议栈里找到这张网卡
		if nic == nil {
			continue
		}

		var ref *referencedNetworkEndpoint
		if len(localAddr) != 0 {
			ref = nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint) // 找到绑定LocalAddr的IP端
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
		logger.GetInstance().Info(logger.IP, func() {
			log.Println(r.LocalLinkAddress, r.LocalAddress, r.RemoteLinkAddress, r.RemoteAddress, r.NextHop)
		})
		log.Println(s.routeTable[i])
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

	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr} // addr 可能是Remote IP Address
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
	logger.GetInstance().Info(logger.UDP|logger.TCP, func() {
		log.Println("往", nicID, "网卡注册新的传输端")
	})
	if nicID == 0 {
		return s.demux.registerEndpoint(netProtos, protocol, id, ep) // 给协议栈的所有网卡注册传输端
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic := s.nics[nicID]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}
	return nic.demux.registerEndpoint(netProtos, protocol, id, ep) // 给这张网卡注册传输端
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(nicID tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	if nicID == 0 {
		s.demux.unregisterEndpoint(netProtos, protocol, id) // 释放协议栈中的传输端
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	nic := s.nics[nicID]
	if nic != nil {
		nic.demux.unregisterEndpoint(netProtos, protocol, id) //释放该网卡中的传输端
	}

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

// JoinGroup joins the given multicast group on the given NIC.
func (s *Stack) JoinGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	// TODO: notify network of subscription via igmp protocol.
	return s.AddAddressWithOptions(nicID, protocol, multicastAddr, NeverPrimaryEndpoint)
}

// LeaveGroup leaves the given multicast group on the given NIC.
func (s *Stack) LeaveGroup(protocol tcpip.NetworkProtocolNumber, nicID tcpip.NICID, multicastAddr tcpip.Address) *tcpip.Error {
	return s.RemoveAddress(nicID, multicastAddr)
}
