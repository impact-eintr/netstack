package udp

import (
	"log"
	"math"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"netstack/waiter"
	"sync"
)

// udp报文结构 当收到udp报文时 会用这个结构来保存udp报文数据
type udpPacket struct {
	udpPacketEntry // 链表实现
	senderAddress  tcpip.FullAddress
	data           buffer.VectorisedView
	timestamp      int64
	hasTimestamp   bool
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View
}

type endpointState int

// 表示UDP端的状态参数
const (
	stateInitial endpointState = iota
	stateBound
	stateConnected
	stateClosed
)

type endpoint struct {
	stack       *stack.Stack                // udp所依赖的用户协议栈
	netProto    tcpip.NetworkProtocolNumber // udp网络协议号 ipv4/ipv6
	waiterQueue *waiter.Queue               // 事件驱动机制

	// The following fields are used to manage the receive queue, and are
	// protected by rcvMu.
	rcvMu         sync.Mutex
	rcvReady      bool
	rcvList       udpPacketList
	rcvBufSizeMax int
	rcvBufSize    int
	rcvClosed     bool
	rcvTimestamp  bool // 通过SetSocket进行设置 是否开启时间戳

	// The following fields are protected by the mu mutex.
	mu           sync.RWMutex
	sndBufSize   int // 发送缓冲区大小
	id           stack.TransportEndpointID
	state        endpointState
	bindNICID    tcpip.NICID // 绑定的网卡
	regNICID     tcpip.NICID //
	route        stack.Route // 路由? TODO
	dstPort      uint16      // 目标端口
	v6only       bool        // 仅支持ipv6
	multicastTTL uint8       // 广播TTL

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	multicastMemberships []multicastMembership

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address). 当前生效的网络层协议
	effectiveNetProtos []tcpip.NetworkProtocolNumber
}

// 多播的成员关系，包括多播地址和网卡ID
type multicastMembership struct {
	nicID         tcpip.NICID
	multicastAddr tcpip.Address
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber,
	waiterQueue *waiter.Queue) *endpoint {
	log.Println("新建一个udp端")
	return &endpoint{
		stack:         stack,
		netProto:      netProto,
		waiterQueue:   waiterQueue,
		multicastTTL:  1,
		rcvBufSizeMax: 32 * 1024, // 接收缓存 32k
		sndBufSize:    32 * 1024, // 发送缓存 32k
	}
}

// NewConnectedEndpoint creates a new endpoint in the connected state using the
// provided route.
func NewConnectedEndpoint(stack *stack.Stack, r *stack.Route, id stack.TransportEndpointID,
	waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	ep := newEndpoint(stack, r.NetProto, waiterQueue)

	// Register new endpoint so that packets are routed to it.
	if err := stack.RegisterTransportEndpoint(r.NICID(),
		[]tcpip.NetworkProtocolNumber{r.NetProto}, ProtocolNumber, id, ep); err != nil {
		ep.Close()
		return nil, err
	}

	ep.id = id
	ep.route = r.Clone()
	ep.dstPort = id.RemotePort
	ep.regNICID = r.NICID()

	ep.state = stateConnected

	return ep, nil
}

// Close UDP端的关闭，释放相应的资源
func (e *endpoint) Close() {
	e.mu.Lock()

	e.shutdownFlags = tcpip.ShutdownRead | tcpip.ShutdownWrite // 关闭读写

	switch e.state {
	case stateBound, stateConnected:
		// 释放在协议栈中注册的UDP端
		e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
		// 释放端口占用
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
	}

	for _, mem := range e.multicastMemberships {
		e.stack.LeaveGroup(e.netProto, mem.nicID, mem.multicastAddr)
	}
	e.multicastMemberships = nil

	// Close the receive list and drain it.
	e.rcvMu.Lock()
	e.rcvClosed = true
	e.rcvBufSize = 0
	// 清空接收链表
	for !e.rcvList.Empty() {
		p := e.rcvList.Front()
		e.rcvList.Remove(p)
	}
	e.rcvMu.Unlock()

	e.route.Release()

	// Update the state.
	e.state = stateClosed

	e.mu.Unlock()
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

func (e *endpoint) Read(addr *tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.rcvMu.Lock()

	// 如果接收链表为空，即没有任何数据
	if e.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if e.rcvClosed {
			err = tcpip.ErrClosedForReceive
		}
		e.rcvMu.Unlock()
		return buffer.View{}, tcpip.ControlMessages{}, err
	}
	// 从接收链表中取出最前面的数据报，接着从链表中删除该数据报
	// 然后减少接收缓存的大小
	p := e.rcvList.Front()
	e.rcvList.Remove(p)
	e.rcvBufSize -= p.data.Size()
	ts := e.rcvTimestamp

	e.rcvMu.Unlock()

	if ts && !p.hasTimestamp {
		// Linux uses the current time.
		p.timestamp = e.stack.NowNanoseconds()
	}
	if addr != nil {
		// 赋值发送地址
		*addr = p.senderAddress
	}

	return p.data.ToView(), tcpip.ControlMessages{HasTimestamp: ts, Timestamp: p.timestamp}, nil
}

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
// 增加UDP头部信息，并发送给给网络层
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8) *tcpip.Error {
	// Allocate a buffer for the UDP header.
	hdr := buffer.NewPrependable(header.UDPMinimumSize + int(r.MaxHeaderLength()))

	// Initialize the header.
	udp := header.UDP(hdr.Prepend(header.UDPMinimumSize))

	// 得到报文的长度
	length := uint16(hdr.UsedLength() + data.Size())
	// UDP首部的编码
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Only calculate the checksum if offloading isn't supported.
	if r.Capabilities()&stack.CapabilityChecksumOffload == 0 {
		// 检验和的计算
		xsum := r.PseudoHeaderChecksum(ProtocolNumber)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum, length))
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()

	// 将准备好的UDP首部和数据写给网络层
	log.Printf("send udp %d bytes", hdr.UsedLength()+data.Size())
	return r.WritePacket(hdr, data, ProtocolNumber, ttl)
}

// 写数据之前的准备，如果还是初始状态需要先进性绑定操作。
func (e *endpoint) prepareForWrite(to *tcpip.FullAddress) (retry bool, err *tcpip.Error) {
	switch e.state {
	case stateInitial:
	case stateConnected:
		return false, nil

	case stateBound:
		if to == nil {
			return false, tcpip.ErrDestinationRequired
		}
		return false, nil
	default:
		return false, tcpip.ErrInvalidEndpointState
	}

	e.mu.RUnlock()
	defer e.mu.RLock()

	e.mu.Lock()
	defer e.mu.Unlock()

	// The state changed when we released the shared locked and re-acquired
	// it in exclusive mode. Try again.
	if e.state != stateInitial {
		return true, nil
	}

	// The state is still 'initial', so try to bind the endpoint.
	// 随机绑定一个端口
	if err := e.bindLocked(tcpip.FullAddress{}, nil); err != nil {
		return false, err
	}

	return true, nil
}

// Write 用户层最终调用该函数，发送数据包给对端，即使数据写失败，也不会阻塞。
func (e *endpoint) Write(p tcpip.Payload, opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	// MSG_MORE is unimplemented. (This also means that MSG_EOR is a no-op.)
	if opts.More {
		return 0, nil, tcpip.ErrInvalidOptionValue
	}
	// NOTE 如果报文长度超过65535，将会超过UDP最大的长度表示，这是不允许的。
	if p.Size() > math.MaxUint16 {
		// Payload can't possibly fit in a packet.
		return 0, nil, tcpip.ErrMessageTooLong
	}
	to := opts.To

	e.mu.RLock()
	defer e.mu.RUnlock()
	log.Println("UDP 准备向 路由", to, "写入数据")
	// If we've shutdown with SHUT_WR we are in an invalid state for sending.
	// 如果设置了关闭写数据，那返回错误
	if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
		return 0, nil, tcpip.ErrClosedForSend
	}

	// Prepare for write.
	// 准备发送数据
	for {
		retry, err := e.prepareForWrite(to)
		if err != nil {
			return 0, nil, err
		}

		if !retry {
			break
		}
	}

	var route *stack.Route
	var dstPort uint16
	if to == nil {
		// 如果没有指定发送的地址，用UDP端 Connect 得到的路由和目的端口
		route = &e.route
		dstPort = e.dstPort

		if route.IsResolutionRequired() {
			// Promote lock to exclusive if using a shared route, given that it may need to
			// change in Route.Resolve() call below.
			// 如果使用共享路由，则将锁定提升为独占路由，因为它可能需要在下面的Route.Resolve（）调用中进行更改。
			e.mu.RUnlock()
			defer e.mu.RLock()

			e.mu.Lock()
			defer e.mu.Unlock()

			// Recheck state after lock was re-acquired.
			// 锁定后重新检查状态。
			if e.state != stateConnected {
				return 0, nil, tcpip.ErrInvalidEndpointState
			}
		}
	} else { // 如果指定了发送地址和端口
		nicid := to.NIC
		// 如果绑定了网卡
		if e.bindNICID != 0 {
			if nicid != 0 && nicid != e.bindNICID {
				return 0, nil, tcpip.ErrNoRoute // 指定了网卡但udp端没绑定这张网卡
			}
			nicid = e.bindNICID // 如果没指定网卡就用这张绑定过的网卡
		}
		// 得到目的IP+端口
		toCopy := *to
		to = &toCopy
		netProto, err := e.checkV4Mapped(to, false)
		if err != nil {
			return 0, nil, err
		}
		// Find the enpoint.
		// 根据目的地址和协议找到相关路由信息
		r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, to.Addr, netProto)
		if err != nil {
			return 0, nil, err
		}
		defer r.Release()

		route = &r
		dstPort = to.Port
	}

	// TODO
	// 如果路由没有下一跳的链路MAC地址，那么触发相应的机制，来填充该路由信息。
	// 比如：IPV4协议，如果没有目的IP对应的MAC信息，从从ARP缓存中查找信息，找到了直接返回，
	// 若没找到，那么发送ARP请求，得到对应的MAC地址。
	if route.IsResolutionRequired() {
		waker := &sleep.Waker{}
		log.Println("发起arp广播(如果目标是255.255.255.255)或者在本地arp缓存来寻找目标主机 目标路由为", to, route.RemoteAddress)
		if ch, err := route.Resolve(waker); err != nil {
			if err == tcpip.ErrWouldBlock {
				// Link address needs to be resolved. Resolution was triggered the background.
				// Better luck next time.
				route.RemoveWaker(waker)
				return 0, ch, tcpip.ErrNoLinkAddress
			}
			return 0, nil, err
		}
	}

	// 得到要发送的数据内容
	v, err := p.Get(p.Size())
	if err != nil {
		return 0, nil, err
	}

	ttl := route.DefaultTTL()
	// 如果是多播地址，设置ttl
	if header.IsV4MulticastAddress(route.RemoteAddress) || header.IsV6MulticastAddress(route.RemoteAddress) {
		ttl = e.multicastTTL
	}

	// 增加UDP头部信息，并发送出去
	if err := sendUDP(route, buffer.View(v).ToVectorisedView(), e.id.LocalPort, dstPort, ttl); err != nil {
		return 0, nil, err
	}

	return uintptr(len(v)), nil, nil
}

func (e *endpoint) Peek([][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// IPV6于IPV4地址的映射
func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress, allowMismatch bool) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto := e.netProto
	if header.IsV4MappedAddress(addr.Addr) {
		// Fail if using a v4 mapped address on a v6only endpoint.
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		netProto = header.IPv4ProtocolNumber
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		if addr.Addr == "\x00\x00\x00\x00" {
			addr.Addr = ""
		}

		// Fail if we are bound to an IPv6 address.
		if !allowMismatch && len(e.id.LocalAddress) == 16 {
			return 0, tcpip.ErrNetworkUnreachable
		}
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	// 源地址用与目标地址使用的ip协议不能不一致
	if l := len(e.id.LocalAddress); l != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Connect UDP中调用connect内核仅仅把对端ip&port记录下来. 这样在发送数据的时候无需再次指定
// UDP多次调用connect有两种用途:1,指定一个新的ip&port连结. 2,断开和之前的ip&port的连结
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	// 目标端口为0是错误的
	if addr.Port == 0 {
		// We don't support connecting to port zero.
		return tcpip.ErrInvalidEndpointState
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	nicid := addr.NIC
	var localPort uint16
	// 判断UDP端的状态
	switch e.state {
	case stateInitial:
		// 如果是初始状态，直接下一步
	case stateBound, stateConnected:
		localPort = e.id.LocalPort
		log.Printf("绑定了 %d 的udp端 向[%d]网卡发起连接\n", localPort, nicid)
		if e.bindNICID == 0 {
			break
		}
		if nicid != 0 && nicid != e.bindNICID {
			return tcpip.ErrInvalidEndpointState
		}
		nicid = e.bindNICID
	default:
		return tcpip.ErrInvalidEndpointState
	}

	// 检查地址的映射，得到相应的协议
	netProto, err := e.checkV4Mapped(&addr, false)
	if err != nil {
		return err
	}
	// Find a route to the desired destination.
	// 在全局协议栈中查找路由
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	// 新建一个传输端的标识，包括源IP、源端口、目的IP、目的端口
	id := stack.TransportEndpointID{
		LocalAddress:  r.LocalAddress,
		LocalPort:     localPort,
		RemotePort:    addr.Port,
		RemoteAddress: r.RemoteAddress,
	}

	// 设置网络层协议，IPV4或IPV6，或两者都有
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv4ProtocolNumber,
			header.IPv6ProtocolNumber,
		}
	}

	// 将该UDP端注册到协议栈中
	id, err = e.registerWithStack(nicid, netProtos, id)
	if err != nil {
		return err
	}
	// Remove the old registration.
	// 如果源端口不为0，则尝试在传输层端中删除老的UDP端
	if e.id.LocalPort != 0 {
		e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
	}

	log.Println(e.id, id)

	// 赋值UDP端的属性
	e.id = id
	e.route = r.Clone()
	e.dstPort = addr.Port
	e.regNICID = nicid
	e.effectiveNetProtos = netProtos

	// 更改该UDP端的状态为已连接
	e.state = stateConnected

	// 标志该UDP端可以接收数据了
	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// A socket in the bound state can still receive multicast messages,
	// so we need to notify waiters on shutdown.
	if e.state != stateBound && e.state != stateConnected {
		return tcpip.ErrNotConnected
	}

	e.shutdownFlags |= flags

	if flags&tcpip.ShutdownRead != 0 {
		e.rcvMu.Lock()
		wasClosed := e.rcvClosed
		e.rcvClosed = true
		e.rcvMu.Unlock()

		if !wasClosed {
			e.waiterQueue.Notify(waiter.EventIn)
		}
	}

	return nil
}

func (e *endpoint) Listen(backlog int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

func (e *endpoint) registerWithStack(nicid tcpip.NICID, netProtos []tcpip.NetworkProtocolNumber,
	id stack.TransportEndpointID) (stack.TransportEndpointID, *tcpip.Error) {
	if e.id.LocalPort == 0 { // 一个没有绑定过端口的udp端
		port, err := e.stack.ReservePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort) // 为这个udp端绑定一个端口
		if err != nil {
			return id, err
		}
		id.LocalPort = port
	}
	err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e) // 往网卡注册一个绑定了端口的udp端
	if err != nil {
		// 释放端口
		e.stack.ReleasePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort)
	}
	return id, err
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	// 不是初始状态的UDP实现不允许绑定
	if e.state != stateInitial {
		return tcpip.ErrInvalidEndpointState
	}

	netProto, err := e.checkV4Mapped(&addr, true)
	if err != nil {
		return nil
	}

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" { // IPv6 && 支持ipv4 & 任意地址
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}

	// 不是任意地址的话 需要检验本地网卡是否绑定个这个ip地址
	if len(addr.Addr) != 0 {
		if e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr) == 0 {
			return tcpip.ErrBadLocalAddress
		}
	}

	// 开始绑定 绑定的时候 传输端ID : srcIP + srcPort
	id := stack.TransportEndpointID{
		LocalAddress: addr.Addr,
		LocalPort:    addr.Port,
	}
	log.Println("Bind", id)
	// 在协议栈中注册该UDP端
	id, err = e.registerWithStack(addr.NIC, netProtos, id)
	if err != nil {
		return err
	}
	// 如果指定了 commit 函数 执行并处理错误
	if commit != nil {
		if err := commit(); err != nil {
			// Unregister, the commit failed.
			e.stack.UnregisterTransportEndpoint(addr.NIC, netProtos, ProtocolNumber, id)
			e.stack.ReleasePort(netProtos, ProtocolNumber, id.LocalAddress, id.LocalPort)
			return err
		}
	}

	e.id = id
	e.regNICID = addr.NIC
	e.effectiveNetProtos = netProtos

	// Mark endpoint as bound.
	// 标记状态为已绑定
	e.state = stateBound

	e.rcvMu.Lock()
	e.rcvReady = true
	e.rcvMu.Unlock()

	return nil
}

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
// Bind 将该UDP端绑定本地的一个IP+端口
// 例如：绑定本地0.0.0.0的9000端口，那么其他机器给这台机器9000端口发消息，该UDP端就能收到消息了
func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 执行绑定IP+端口操作
	err := e.bindLocked(addr, commit)
	if err != nil {
		return err
	}

	// 绑定的网卡ID
	e.bindNICID = addr.NIC
	return nil
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
	}, nil
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
	}

	return tcpip.FullAddress{
		NIC:  e.regNICID,
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
	}, nil
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.EventOut & mask

	// Determine if the endpoint is readable if requested.
	if (mask & waiter.EventIn) != 0 {
		e.rcvMu.Lock()
		if !e.rcvList.Empty() || e.rcvClosed {
			result |= waiter.EventIn
		}
		e.rcvMu.Unlock()
	}

	return result
}

func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != stateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0

	case tcpip.TimestampOption:
		e.rcvMu.Lock()
		e.rcvTimestamp = v != 0
		e.rcvMu.Unlock()

	case tcpip.MulticastTTLOption:
		e.mu.Lock()
		e.multicastTTL = uint8(v)
		e.mu.Unlock()

	case tcpip.AddMembershipOption:
		nicID := v.NIC
		if v.InterfaceAddr != header.IPv4Any {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrNoRoute
		}

		// TODO: check that v.MulticastAddr is a multicast address.
		if err := e.stack.JoinGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		e.multicastMemberships = append(e.multicastMemberships, multicastMembership{nicID, v.MulticastAddr})

	case tcpip.RemoveMembershipOption:
		nicID := v.NIC
		if v.InterfaceAddr != header.IPv4Any {
			nicID = e.stack.CheckLocalAddress(nicID, e.netProto, v.InterfaceAddr)
		}
		if nicID == 0 {
			return tcpip.ErrNoRoute
		}

		// TODO: check that v.MulticastAddr is a multicast address.
		if err := e.stack.LeaveGroup(e.netProto, nicID, v.MulticastAddr); err != nil {
			return err
		}

		e.mu.Lock()
		defer e.mu.Unlock()
		for i, mem := range e.multicastMemberships {
			if mem.nicID == nicID && mem.multicastAddr == v.MulticastAddr {
				// Only remove the first match, so that each added membership above is
				// paired with exactly 1 removal.
				e.multicastMemberships[i] = e.multicastMemberships[len(e.multicastMemberships)-1]
				e.multicastMemberships = e.multicastMemberships[:len(e.multicastMemberships)-1]
				break
			}
		}
	}
	return nil
}

func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil

	case *tcpip.SendBufferSizeOption:
		e.mu.Lock()
		*o = tcpip.SendBufferSizeOption(e.sndBufSize)
		e.mu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.rcvMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSizeMax)
		e.rcvMu.Unlock()
		return nil

	case *tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		e.rcvMu.Lock()
		if e.rcvList.Empty() {
			*o = 0
		} else {
			p := e.rcvList.Front()
			*o = tcpip.ReceiveQueueSizeOption(p.data.Size())
		}
		e.rcvMu.Unlock()
		return nil

	case *tcpip.TimestampOption:
		e.rcvMu.Lock()
		*o = 0
		if e.rcvTimestamp {
			*o = 1
		}
		e.rcvMu.Unlock()

	case *tcpip.MulticastTTLOption:
		e.mu.Lock()
		*o = tcpip.MulticastTTLOption(e.multicastTTL)
		e.mu.Unlock()
		return nil
	}

	return tcpip.ErrUnknownProtocolOption
}

// HandlePacket 从网络层接收到UDP数据报时的处理函数
// 首先 UDP 端有接收队列的概念，不像网络层接收到数据包立马发送给传输层，
// 对于协议栈来说，传输层是最后的一站，接下来的数据就需要交给用户层了，
// 但是用户层的行为是不可预知的，不知道用户层何时将数据取走（也就是 UDP Read 过程），
// 那么协议栈就实现一个接收队列，将接收的数据去掉 UDP 头部后保存在这个队列中，用户层需要的时候取走就可以了，
// 但是队列存数据量是有限制的，这个限制叫接收缓存大小，当接收队列中的数据总和超过这个缓存，那么接下来的这些报文将会被直接丢包。
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	// Get the header then trim it from the view.
	hdr := header.UDP(vv.ToView())
	if int(hdr.Length()) > vv.Size() {
		// Malformed packet.
		// 错误报文
		e.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return
	}

	log.Println("udp 正式接收数据", hdr)
	// 去除UDP首部
	vv.TrimFront(header.UDPMinimumSize)

	e.rcvMu.Lock()
	e.stack.Stats().UDP.PacketsReceived.Increment()

	// Drop the packet if our buffer is currently full.
	// 如果UDP的接收缓存已经满了，那么丢弃报文。
	if !e.rcvReady || e.rcvClosed || e.rcvBufSize >= e.rcvBufSizeMax {
		e.stack.Stats().UDP.ReceiveBufferErrors.Increment()
		e.rcvMu.Unlock()
		log.Println("udp 接收缓存不足 丢弃报文")
		return
	}

	// 接收缓存是否为空
	wasEmpty := e.rcvBufSize == 0
	// 新建一个UDP数据包结构 插入到接收链表中
	pkt := &udpPacket{
		senderAddress: tcpip.FullAddress{
			NIC:  r.NICID(),
			Addr: id.RemoteAddress,
			Port: hdr.SourcePort(),
		},
	}
	// 复制UDP数据包的用户数据
	pkt.data = vv.Clone(pkt.views[:]) // 当vv中的数据<=8时 无需再次分配内存
	// 插入到接收链表中 并增加已经使用的缓存
	e.rcvList.PushBack(pkt)
	e.rcvBufSize += vv.Size()

	if e.rcvTimestamp {
		pkt.timestamp = e.stack.NowNanoseconds()
		pkt.hasTimestamp = true
	}

	e.rcvMu.Unlock()
	// NOTE 通知用户层可以读取数据了
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
}
