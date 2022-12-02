package udp

import (
	"log"
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
	waiterQueue *waiter.Queue               // TODO 需要解析

	// TODO 需要解析
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

	e.shutdownFlags = tcpip.ShutdownRead | tcpip.ShutdownWrite

	switch e.state {
	case stateBound, stateConnected:
		// 释放在协议栈中注册的UDP端
		e.stack.UnregisterTransportEndpoint(e.regNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
		// 释放端口占用
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
	}

	// TODO
	e.mu.Unlock()
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

func (e *endpoint) Write(tcpip.Payload, tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	return 0, nil, nil
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
	return nil
}

func (e *endpoint) Listen(backlog int) *tcpip.Error {
	return nil
}

func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, nil
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
	return tcpip.FullAddress{}, nil
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return waiter.EventErr
}

func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

// HandlePacket 从网络层接收到UDP数据报时的处理函数
// 首先 UDP 端有接收队列的概念，不像网络层接收到数据包立马发送给传输层，
// 对于协议栈来说，传输层是最后的一站，接下来的数据就需要交给用户层了，
// 但是用户层的行为是不可预知的，不知道用户层何时将数据取走（也就是 UDP Read 过程），
// 那么协议栈就实现一个接收队列，将接收的数据去掉 UDP 头部后保存在这个队列中，用户层需要的时候取走就可以了，
// 但是队列存数据量是有限制的，这个限制叫接收缓存大小，当接收队列中的数据总和超过这个缓存，那么接下来的这些报文将会被直接丢包。
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	// Get the header then trim it from the view.
	hdr := header.UDP(vv.First())
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
	// TODO 通知用户层可以读取数据了
	if wasEmpty {
		e.waiterQueue.Notify(waiter.EventIn)
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
}
