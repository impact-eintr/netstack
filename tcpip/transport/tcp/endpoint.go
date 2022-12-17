package tcp

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"netstack/logger"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
	"netstack/tmutex"
	"netstack/waiter"
	"sync"
	"sync/atomic"
	"time"
)

// tcp状态机的状态
type endpointState int

// tcp 状态机的各种状态
const (
	stateInitial endpointState = iota
	stateBound
	stateListen
	stateConnecting
	stateConnected
	stateClosed
	stateError
)

// Reasons for notifying the protocol goroutine.
const (
	notifyNonZeroReceiveWindow = 1 << iota
	notifyReceiveWindowChanged
	notifyClose
	notifyMTUChanged
	notifyDrain
	notifyReset
	notifyKeepaliveChanged
)

// SACKInfo holds TCP SACK related information for a given endpoint.
//
// +stateify savable
type SACKInfo struct {
	// Blocks is the maximum number of SACK blocks we track
	// per endpoint.
	Blocks [MaxSACKBlocks]header.SACKBlock

	// NumBlocks is the number of valid SACK blocks stored in the
	// blocks array above.
	NumBlocks int
}

// keepalive is a synchronization wrapper used to appease stateify. See the
// comment in endpoint, where it is used.
// KeepAlive默认情况下是关闭的，可以被上层应用开启和关闭
// tcp_keepalive_probes: 在tcp_keepalive_time之后，没有接收到对方确认，继续发送保活探测包次数，默认值为9（次）
// +stateify savable
type keepalive struct {
	sync.Mutex
	enabled bool
	// KeepAlive的空闲时长，或者说每次正常发送心跳的周期，默认值为7200s（2小时）
	idle time.Duration
	// KeepAlive探测包的发送间隔，默认值为75s
	interval time.Duration
	count    int
	unacked  int
	timer    timer
	waker    sleep.Waker
}

// endpoint 表示TCP端点。该结构用作端点用户和协议实现之间的接口;让并发goroutine调用端点是合法的，
// 它们是正确同步的。然而，协议实现在单个goroutine中运行。
type endpoint struct {
	workMu tmutex.Mutex

	stack       *stack.Stack                // 网络协议栈
	netProto    tcpip.NetworkProtocolNumber // 网络协议号 ipv4 ipv6
	waiterQueue *waiter.Queue               // 事件驱动机制

	// lastError represents the last error that the endpoint reported;
	// access to it is protected by the following mutex.
	lastErrorMu sync.Mutex
	lastError   *tcpip.Error

	// TODO 需要添加

	// rcvListMu can be taken after the endpoint mu below.
	rcvListMu  sync.Mutex
	rcvList    segmentList
	rcvClosed  bool
	rcvBufSize int
	rcvBufUsed int

	// The following fields are protected by the mutex.
	mu                sync.RWMutex
	id                stack.TransportEndpointID // tcp端在网络协议栈的唯一ID
	state             endpointState             // 目前tcp状态机的状态
	isPortReserved    bool                      // 是否已经分配端口
	isRegistered      bool                      // 是否已经注册在网络协议栈
	boundNICID        tcpip.NICID
	route             stack.Route // tcp端在网络协议栈中的路由地址
	v6only            bool        // 是否仅仅支持ipv6
	isConnectNotified bool

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	hardError *tcpip.Error

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// sendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1
	sendTSOk bool

	// recentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	recentTS uint32

	// tsOffset is a randomized offset added to the value of the
	// TSVal field in the timestamp option.
	tsOffset uint32

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// sackPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	sackPermitted bool

	sack SACKInfo

	segmentQueue segmentQueue

	// When the send side is closed, the protocol goroutine is notified via
	// sndCloseWaker, and sndClosed is set to true.
	sndBufMu      sync.Mutex
	sndBufSize    int
	sndBufUsed    int
	sndClosed     bool
	sndBufInQueue seqnum.Size
	sndQueue      segmentList
	sndWaker      sleep.Waker
	sndCloseWaker sleep.Waker

	// cc stores the name of the Congestion Control algorithm to use for
	// this endpoint.
	cc CongestionControlOption

	// The following are used when a "packet too big" control packet is
	// received. They are protected by sndBufMu. They are used to
	// communicate to the main protocol goroutine how many such control
	// messages have been received since the last notification was processed
	// and what was the smallest MTU seen
	packetTooBigCount int
	sndMTU            int

	// newSegmentWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and handle new segments queued to it.
	// HandlePacket收到segment后通知处理的事件驱动器
	newSegmentWaker sleep.Waker

	// notificationWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and check for notifications.
	notificationWaker sleep.Waker

	// notifyFlags is a bitmask of flags used to indicate to the protocol
	// goroutine what it was notified; this is only accessed atomically.
	notifyFlags uint32

	// acceptedChan is used by a listening endpoint protocol goroutine to
	// send newly accepted connections to the endpoint so that they can be
	// read by Accept() calls.
	acceptedChan chan *endpoint

	keepalive keepalive

	// The following are only used from the protocol goroutine, and
	// therefore don't need locks to protect them.
	rcv *receiver
	snd *sender

	// probe if not nil is invoked on every received segment. It is passed
	// a copy of the current state of the endpoint.
	probe stack.TCPProbeFunc

	// The following are only used to assist the restore run to re-connect.
	bindAddress       tcpip.Address
	connectingAddress tcpip.Address
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
		rcvBufSize:  DefaultBufferSize,
		sndBufSize:  DefaultBufferSize,
		sndMTU:      int(math.MaxInt32),
		keepalive: keepalive{
			// Linux defaults.
			idle:     2 * time.Hour,
			interval: 75 * time.Second,
			count:    9,
		},
	}

	var ss SendBufferSizeOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.sndBufSize = ss.Default
	}

	var rs ReceiveBufferSizeOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.rcvBufSize = rs.Default
	}

	var cs CongestionControlOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	e.segmentQueue.setLimit(2 * e.rcvBufSize)
	e.workMu.Init()
	e.workMu.Lock()
	e.tsOffset = timeStampOffset() // 随机偏移
	return e
}

func (e *endpoint) fetchNotifications() uint32 {
	return atomic.SwapUint32(&e.notifyFlags, 0)
}

// 通知订阅消息的任务开始工作
func (e *endpoint) notifyProtocolGoroutine(n uint32) {
	for {
		v := atomic.LoadUint32(&e.notifyFlags)
		if v&n == n {
			// The flags are already set.
			return
		}

		if atomic.CompareAndSwapUint32(&e.notifyFlags, v, v|n) {
			if v == 0 {
				// We are causing a transition from no flags to
				// at least one flag set, so we must cause the
				// protocol goroutine to wake up.
				e.notificationWaker.Assert()
			}
			return
		}
	}
}

func (e *endpoint) Close() {
	e.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	e.mu.Lock()

	// We always release ports inline so that they are immediately available
	// for reuse after Close() is called. If also registered, it means this
	// is a listening socket, so we must unregister as well otherwise the
	// next user would fail in Listen() when trying to register.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
		e.isPortReserved = false

		if e.isRegistered {
			e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
			e.isRegistered = false
		}
	}

	logger.TODO("添加清理资源的逻辑")
	e.mu.Unlock()
}

// Read 从tcp的接收队列中读取数据
func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()

	e.rcvListMu.Lock()
	bufUsed := e.rcvBufUsed
	if s := e.state; s != stateConnected && s != stateClosed && bufUsed == 0 {
		e.rcvListMu.Unlock()
		he := e.hardError
		e.mu.RUnlock()
		if s == stateError {
			return buffer.View{}, tcpip.ControlMessages{}, he
		}
		return buffer.View{}, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	v, err := e.readLocked()
	e.rcvListMu.Unlock()
	e.mu.RUnlock()
	return v, tcpip.ControlMessages{}, err
}

// 从tcp的接收队列中读取数据，并从接收队列中删除已读数据
func (e *endpoint) readLocked() (buffer.View, *tcpip.Error) {
	if e.rcvBufUsed == 0 {
		if e.rcvClosed || e.state != stateConnected {
			return buffer.View{}, tcpip.ErrClosedForReceive
		}
		return buffer.View{}, tcpip.ErrWouldBlock
	}
	s := e.rcvList.Front()
	views := s.data.Views()
	v := views[s.viewToDeliver]
	s.viewToDeliver++

	if s.viewToDeliver >= len(views) {
		e.rcvList.Remove(s)
		s.decRef()
	}

	scale := e.rcv.rcvWndScale
	// 检测接收窗口是否为0
	wasZero := e.zeroReceiveWindow(scale) // 取用数据前是否有空闲
	e.rcvBufUsed -= len(v)
	if wasZero && !e.zeroReceiveWindow(scale) { // 之前没空闲 现在有了 告知一下对端
		e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
	}

	return v, nil
}

// Write 接收上层的数据，通过tcp连接发送到对端
func (e *endpoint) Write(p tcpip.Payload, opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// 判断tcp状态，必须已经建立了连接才能发送数据
	if e.state != stateConnected {
		switch e.state {
		case stateError:
			return 0, nil, e.hardError
		default:
			return 0, nil, tcpip.ErrClosedForSend
		}
	}
	// 检查负载的长度，如果为0，直接返回
	if p.Size() == 0 {
		return 0, nil, nil
	}
	e.sndBufMu.Lock()
	// Check if the connection has already been closed for sends.
	if e.sndClosed {
		e.sndBufMu.Unlock()
		return 0, nil, tcpip.ErrClosedForSend
	}

	// tcp流量控制：未被占用发送缓存还剩多少，如果发送缓存已经被用光了，返回 ErrWouldBlock
	avail := e.sndBufSize - e.sndBufUsed
	if avail <= 0 {
		e.sndBufMu.Unlock()
		return 0, nil, tcpip.ErrWouldBlock
	}

	v, perr := p.Get(avail)
	if perr != nil {
		e.sndBufMu.Unlock()
		return 0, nil, perr
	}
	var err *tcpip.Error
	if p.Size() > avail { // 给的数据 缓存不足以容纳
		err = tcpip.ErrWouldBlock
	}
	l := len(v)
	s := newSegmentFromView(&e.route, e.id, v) // 分段
	// 插入发送队列
	e.sndBufUsed += l
	e.sndBufInQueue += seqnum.Size(l)
	e.sndQueue.PushBack(s)

	e.sndBufMu.Unlock()

	// 发送数据，最终会调用 sender sendData 来发送数据
	if e.workMu.TryLock() {
		// Do the work inline.
		e.handleWrite()
		e.workMu.Unlock()
	} else {
		// Let the protocol goroutine do the work.
		e.sndWaker.Assert()
	}

	return uintptr(l), nil, err
}

func (e *endpoint) Peek([][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
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
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	if l := len(e.id.LocalAddress); l != 0 && len(addr.Addr) != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Connect 这是客户端用的吧
func (e *endpoint) Connect(address tcpip.FullAddress) *tcpip.Error {
	return e.connect(address, true, true)
}

// connect将端点连接到其对等端。在正常的非S/R情况下，新连接应该运行主goroutine并执行握手。
// 在恢复先前连接的端点时，将被动地创建两端（因此不会进行新的握手）;对于应用程序尚未接受的堆栈接受连接，
// 它们将在不运行主goroutine的情况下进行恢复。
func (e *endpoint) connect(addr tcpip.FullAddress, handshake bool, run bool) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil && !err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		}
	}()

	connectingAddr := addr.Addr

	// 检查ipv4是否映射到ipv6
	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}

	nicid := addr.NIC
	// 判断连接的状态
	switch e.state {
	case stateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicid != 0 && nicid != e.boundNICID {
			return tcpip.ErrNoRoute
		}

		nicid = e.boundNICID

	case stateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID
		// (if any) when we find a route.

	case stateConnecting:
		// A connection request has already been issued but hasn't
		// completed yet.
		return tcpip.ErrAlreadyConnecting

	case stateConnected:
		// The endpoint is already connected. If caller hasn't been notified yet, return success.
		if !e.isConnectNotified {
			e.isConnectNotified = true
			return nil
		}
		// Otherwise return that it's already connected.
		return tcpip.ErrAlreadyConnected

	case stateError:
		return e.hardError

	default:
		return tcpip.ErrInvalidEndpointState
	}

	// Find a route to the desired destination.
	// 根据目标ip查找路由信息
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	origID := e.id

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	e.id.LocalAddress = r.LocalAddress
	e.id.RemoteAddress = r.RemoteAddress
	e.id.RemotePort = addr.Port

	if e.id.LocalPort != 0 {
		// 记录和检查原端口是否已被使用
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, e.id, e)
		if err != nil {
			return err
		}
	} else {
		// 端点还没有本地端口，所以尝试获取一个端口。确保它不会导致本地和远程的相同地址/端口（否则此端点将尝试连接到自身）
		// 远端地址和本地地址是否相同
		// NOTE 这段代码值得借鉴
		sameAddr := e.id.LocalAddress == e.id.RemoteAddress
		if _, err := e.stack.PickEphemeralPort(func(p uint16) (bool, *tcpip.Error) {
			if sameAddr && p == e.id.RemotePort { // 同样的ip同样的port 打咩捏
				return false, nil
			}
			if !e.stack.IsPortAvailable(netProtos, ProtocolNumber, e.id.LocalAddress, p) { // 端口被占用打咩
				return false, nil
			}
			id := e.id
			id.LocalPort = p
			switch e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e) {
			case nil:
				e.id = id
				return true, nil
			case tcpip.ErrPortInUse:
				return false, nil
			default:
				return false, err
			}
		}); err != nil {
			return err
		}
	}

	// Remove the port reservation. This can happen when Bind is called
	// before Connect: in such a case we don't want to hold on to
	// reservations anymore.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, origID.LocalAddress, origID.LocalPort)
		e.isPortReserved = false
	}

	// 记录该端点的参数
	e.isRegistered = true
	e.state = stateConnecting
	e.route = r.Clone()
	e.boundNICID = nicid
	e.effectiveNetProtos = netProtos
	e.connectingAddress = connectingAddr

	// Connect in the restore phase does not perform handshake. Restore its
	// connection setting here.
	if !handshake {
		//e.segmentQueue.mu.Lock()
		//for _, l := range []segmentList{e.segmentQueue.list, e.sndQueue, e.snd.writeList} {
		//	for s := l.Front(); s != nil; s = s.Next() {
		//		s.id = e.id
		//		s.route = r.Clone()
		//		e.sndWaker.Assert()
		//	}
		//}
		//e.segmentQueue.mu.Unlock()
		//e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		//e.state = stateConnected
	}

	if run {
		e.workerRunning = true
		e.stack.Stats().TCP.ActiveConnectionOpenings.Increment()
		// tcp的主函数
		go e.protocolMainLoop(handshake)
	}

	return tcpip.ErrConnectStarted
}

func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdownFlags |= flags

	switch e.state {
	case stateConnected: // 客户端关闭
		// 不能直接关闭读数据包，因为关闭连接的时候四次挥手还需要读取报文。
		if (e.shutdownFlags & tcpip.ShutdownWrite) != 0 {
			e.rcvListMu.Lock()
			rcvBufUsed := e.rcvBufUsed
			e.rcvListMu.Unlock()
			if rcvBufUsed > 0 {
				// 如果接收队列中还有数据 通知对端RESET
				logger.TODO("通知对端RESET")
				return nil
			}
		}

		e.sndBufMu.Lock()
		if e.sndClosed {
			// Already closed.
			e.sndBufMu.Unlock()
			break
		}

		// Queue fin segment.
		s := newSegmentFromView(&e.route, e.id, nil)
		e.sndQueue.PushBack(s)
		e.sndBufInQueue++ // 仅仅占用一个字节位置
		// Mark endpoint as closed.
		e.sndClosed = true
		e.sndBufMu.Unlock()

		// 触发调用 handleClose
		e.sndCloseWaker.Assert()
	case stateListen: // 服务端关闭
		logger.FIXME("添加服务端关闭逻辑")
	default:
		return tcpip.ErrNotConnected
	}
	return nil
}

func (e *endpoint) Listen(backlog int) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil && err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		}
	}()

	// TODO 需要添加

	// 在调用 Listen 之前，必须先 Bind
	if e.state != stateBound {
		return tcpip.ErrInvalidEndpointState
	}
	// 注册该端点，这样网络层在分发数据包的时候就可以根据 id 来找到这个端点，接着把报文发送给这个端点。
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID,
		e.effectiveNetProtos, ProtocolNumber, e.id, e); err != nil {
		return err
	}

	e.isRegistered = true
	e.state = stateListen
	if e.acceptedChan == nil {
		e.acceptedChan = make(chan *endpoint, backlog)
	}
	e.workerRunning = true

	e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
	// tcp服务端实现的主循环，这个函数很重要，用一个goroutine来服务
	go e.protocolListenLoop(seqnum.Size(e.receiveBufferAvailable()))

	return nil
}

// startAcceptedLoop sets up required state and starts a goroutine with the
// main loop for accepted connections.
func (e *endpoint) startAcceptedLoop(waiterQueue *waiter.Queue) {
	e.waiterQueue = waiterQueue
	e.workerRunning = true
	go e.protocolMainLoop(false)
}

func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Endpoint must be in listen state before it can accept connections.
	if e.state != stateListen {
		return nil, nil, tcpip.ErrInvalidEndpointState
	}

	var n *endpoint
	select {
	case n = <-e.acceptedChan: // 外部再次调用后尝试取出ep
		logger.GetInstance().Info(logger.TCP, func() {
			log.Println("监听者进行一个新连接的分发", n.id)
		})
	default:
		return nil, nil, tcpip.ErrWouldBlock
	}
	wq := &waiter.Queue{}
	n.startAcceptedLoop(wq)
	return n, wq, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
// 将端点绑定到特定的本地端口和可选的地址。
func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 如果端点不是处于初始状态，则不允许绑定。这是因为一旦端点进入连接或监听状态，它就已经绑定了。
	if e.state != stateInitial {
		return tcpip.ErrAlreadyBound
	}
	// 确定tcp端的绑定ip
	e.bindAddress = addr.Addr
	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}
	// 确定tcp支持的网络层协议
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}
	// 绑定端口
	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port)
	if err != nil {
		return err
	}
	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.id.LocalPort = port

	defer func() {
		// 如果有错，在退出的时候应该解除端口绑定
		if err != nil {
			e.stack.ReleasePort(netProtos, ProtocolNumber, addr.Addr, port)
			e.isPortReserved = false
			e.effectiveNetProtos = nil
			e.id.LocalPort = 0
			e.id.LocalAddress = ""
			e.boundNICID = 0
		}
	}()
	// 如果指定了ip地址 需要检查一下这个ip地址本地是否绑定过
	if len(addr.Addr) != 0 {
		nic := e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nic == 0 {
			return tcpip.ErrBadLocalAddress
		}

		e.boundNICID = nic
		e.id.LocalAddress = addr.Addr
	}

	// Check the commit function.
	if commit != nil {
		if err := commit(); err != nil {
			// The defer takes care of unwind.
			return err
		}
	}
	// 标记状态为 stateBound
	e.state = stateBound

	return nil
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
	}

	return tcpip.FullAddress{
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
		NIC:  e.boundNICID,
	}, nil
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.EventMask(0)

	e.mu.RLock()
	defer e.mu.RUnlock()

	switch e.state {
	case stateInitial, stateBound, stateConnecting:
		// Ready for nothing.

	case stateClosed, stateError:
		// Ready for anything.
		result = mask

	case stateListen:
		// Check if there's anything in the accepted channel.
		if (mask & waiter.EventIn) != 0 {
			if len(e.acceptedChan) > 0 {
				result |= waiter.EventIn
			}
		}

	case stateConnected:
		// Determine if the endpoint is writable if requested.
		if (mask & waiter.EventOut) != 0 {
			e.sndBufMu.Lock()
			if e.sndClosed || e.sndBufUsed < e.sndBufSize {
				result |= waiter.EventOut
			}
			e.sndBufMu.Unlock()
		}

		// Determine if the endpoint is readable if requested.
		if (mask & waiter.EventIn) != 0 {
			e.rcvListMu.Lock()
			if e.rcvBufUsed > 0 || e.rcvClosed {
				result |= waiter.EventIn
			}
			e.rcvListMu.Unlock()
		}
	}

	return result
}

// zeroReceiveWindow 根据可用缓冲区的数量和接收窗口缩放，检查现在要宣布的接收窗口是否为零。
func (e *endpoint) zeroReceiveWindow(scale uint8) bool {
	if e.rcvBufUsed >= e.rcvBufSize { // 接收方没接收空间了
		return true
	}
	return ((e.rcvBufSize - e.rcvBufUsed) >> scale) == 0 // 接收方接收空间告急
}

// SetSockOpt sets a socket option
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.KeepaliveEnabledOption:
		e.keepalive.Lock()
		e.keepalive.enabled = v != 0
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		e.keepalive.count = int(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

		//case tcpip.NoDelayOption:
		//	e.mu.Lock()
		//	e.noDelay = v != 0
		//	e.mu.Unlock()
		//	return nil

		//case tcpip.ReuseAddressOption:
		//	e.mu.Lock()
		//	e.reuseAddr = v != 0
		//	e.mu.Unlock()
		//	return nil

		//case tcpip.ReceiveBufferSizeOption:
		//	// Make sure the receive buffer size is within the min and max
		//	// allowed.
		//	var rs ReceiveBufferSizeOption
		//	size := int(v)
		//	if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		//		if size < rs.Min {
		//			size = rs.Min
		//		}
		//		if size > rs.Max {
		//			size = rs.Max
		//		}
		//	}

		//	mask := uint32(notifyReceiveWindowChanged)

		//	e.rcvListMu.Lock()

		//	// Make sure the receive buffer size allows us to send a
		//	// non-zero window size.
		//	scale := uint8(0)
		//	if e.rcv != nil {
		//		scale = e.rcv.rcvWndScale
		//	}
		//	if size>>scale == 0 {
		//		size = 1 << scale
		//	}

		//	// Make sure 2*size doesn't overflow.
		//	if size > math.MaxInt32/2 {
		//		size = math.MaxInt32 / 2
		//	}

		//	wasZero := e.zeroReceiveWindow(scale)
		//	e.rcvBufSize = size
		//	if wasZero && !e.zeroReceiveWindow(scale) {
		//		mask |= notifyNonZeroReceiveWindow
		//	}
		//	e.rcvListMu.Unlock()

		//	e.segmentQueue.setLimit(2 * size)

		//	e.notifyProtocolGoroutine(mask)
		//	return nil

		//case tcpip.SendBufferSizeOption:
		//	// Make sure the send buffer size is within the min and max
		//	// allowed.
		//	size := int(v)
		//	var ss SendBufferSizeOption
		//	if err := e.stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		//		if size < ss.Min {
		//			size = ss.Min
		//		}
		//		if size > ss.Max {
		//			size = ss.Max
		//		}
		//	}

		//	e.sndBufMu.Lock()
		//	e.sndBufSize = size
		//	e.sndBufMu.Unlock()

		//	return nil

		//case tcpip.V6OnlyOption:
		//	// We only recognize this option on v6 endpoints.
		//	if e.netProto != header.IPv6ProtocolNumber {
		//		return tcpip.ErrInvalidEndpointState
		//	}

		//	e.mu.Lock()
		//	defer e.mu.Unlock()

		//	// We only allow this to be set when we're in the initial state.
		//	if e.state != stateInitial {
		//		return tcpip.ErrInvalidEndpointState
		//	}

		//	e.v6only = v != 0

	}

	return nil
}

func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		e.lastErrorMu.Lock()
		err := e.lastError
		e.lastError = nil
		e.lastErrorMu.Unlock()
		return err

	case *tcpip.SendBufferSizeOption:
		e.sndBufMu.Lock()
		*o = tcpip.SendBufferSizeOption(e.sndBufSize)
		e.sndBufMu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.rcvListMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSize)
		e.rcvListMu.Unlock()
		return nil

	//case *tcpip.ReceiveQueueSizeOption:
	//	v, err := e.readyReceiveSize()
	//	if err != nil {
	//		return err
	//	}

	//	*o = tcpip.ReceiveQueueSizeOption(v)
	//	return nil

	//case *tcpip.NoDelayOption:
	//	e.mu.RLock()
	//	v := e.noDelay
	//	e.mu.RUnlock()

	//	*o = 0
	//	if v {
	//		*o = 1
	//	}
	//	return nil

	//case *tcpip.ReuseAddressOption:
	//	e.mu.RLock()
	//	v := e.reuseAddr
	//	e.mu.RUnlock()

	//	*o = 0
	//	if v {
	//		*o = 1
	//	}
	//	return nil

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

	case *tcpip.TCPInfoOption:
		*o = tcpip.TCPInfoOption{}
		e.mu.RLock()
		snd := e.snd
		e.mu.RUnlock()
		if snd != nil {
			snd.rtt.Lock()
			o.RTT = snd.rtt.srtt
			o.RTTVar = snd.rtt.rttvar
			snd.rtt.Unlock()
		}

		return nil

	case *tcpip.KeepaliveEnabledOption:
		e.keepalive.Lock()
		v := e.keepalive.enabled
		e.keepalive.Unlock()

		*o = 0
		if v {
			*o = 1
		}

	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIdleOption(e.keepalive.idle)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIntervalOption(e.keepalive.interval)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveCountOption(e.keepalive.count)
		e.keepalive.Unlock()

	}

	return tcpip.ErrUnknownProtocolOption
}

func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	s := newSegment(r, id, vv)
	// 解析tcp段，如果解析失败，丢弃该报文
	if !s.parse() {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		s.decRef()
		return
	}

	e.stack.Stats().TCP.ValidSegmentsReceived.Increment() // 有效报文喜加一
	if (s.flags & flagRst) != 0 {                         // RST报文需要拒绝
		e.stack.Stats().TCP.ResetsReceived.Increment()
	}
	// Send packet to worker goroutine.
	if e.segmentQueue.enqueue(s) {
		var prefix string = "tcp连接"
		if _, err := e.GetRemoteAddress(); err != nil {
			prefix = "监听者"
		}
		logger.GetInstance().Info(logger.TCP, func() {
			log.Printf(prefix+"收到 tcp [%s] 报文片段 from %s, seq: %d, ack: |%d|",
				flagString(s.flags), fmt.Sprintf("%s:%d", s.id.RemoteAddress, s.id.RemotePort),
				s.sequenceNumber, s.ackNumber)
		})

		// 对于 端口监听者 listener 而言这里唤醒的是 protocolListenLoop
		// 对于普通tcp连接 conn 而言这里唤醒的是 protocolMainLoop
		e.newSegmentWaker.Assert()
	} else {
		// The queue is full, so we drop the segment.
		e.stack.Stats().DroppedPackets.Increment()
		s.decRef()
	}
}

func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {

}

// 当收到ack确认时 需要更新发送确认缓冲占用
func (e *endpoint) updateSndBufferUsage(v int) {
	e.sndBufMu.Lock()
	notify := e.sndBufUsed >= e.sndBufSize>>1
	e.sndBufUsed -= v
	notify = notify && e.sndBufUsed < e.sndBufSize>>1
	e.sndBufMu.Unlock()
	if notify { // 如果缓存中剩余的数据过多是不需要补充的
		e.waiterQueue.Notify(waiter.EventOut)
		log.Println("提醒 用户层的 Write() 继续写入")
	}
}

func (e *endpoint) readyToRead(s *segment) {
	e.rcvListMu.Lock()
	if s != nil {
		s.incRef()
		e.rcvBufUsed += s.data.Size()
		e.rcvList.PushBack(s)
	} else {
		e.rcvClosed = true
	}
	e.rcvListMu.Unlock()

	e.waiterQueue.Notify(waiter.EventIn)
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer.
// tcp流量控制：计算未被占用的接收缓存大小
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	used := e.rcvBufUsed
	e.rcvListMu.Unlock()
	// We may use more bytes than the buffer size when the receive buffer
	// shrinks.
	if used >= size {
		return 0
	}
	return size - used
}

func (e *endpoint) receiveBufferSize() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	e.rcvListMu.Unlock()
	return size
}

// maybeEnableTimestamp marks the timestamp option enabled for this endpoint if
// the SYN options indicate that timestamp option was negotiated. It also
// initializes the recentTS with the value provided in synOpts.TSval.
func (e *endpoint) maybeEnableTimestamp(synOpts *header.TCPSynOptions) {
	if synOpts.TS {
		e.sendTSOk = true
		e.recentTS = synOpts.TSVal
	}
}

// timestamp returns the timestamp value to be used in the TSVal field of the
// timestamp option for outgoing TCP segments for a given endpoint.
func (e *endpoint) timestamp() uint32 {
	return tcpTimeStamp(e.tsOffset)
}

// tcpTimeStamp returns a timestamp offset by the provided offset. This is
// not inlined above as it's used when SYN cookies are in use and endpoint
// is not created at the time when the SYN cookie is sent.
func tcpTimeStamp(offset uint32) uint32 {
	now := time.Now()
	return uint32(now.Unix()*1000+int64(now.Nanosecond()/1e6)) + offset
}

// timeStampOffset returns a randomized timestamp offset to be used when sending
// timestamp values in a timestamp option for a TCP segment.
func timeStampOffset() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// Initialize a random tsOffset that will be added to the recentTS
	// everytime the timestamp is sent when the Timestamp option is enabled.
	//
	// See https://tools.ietf.org/html/rfc7323#section-5.4 for details on
	// why this is required.
	//
	// NOTE: This is not completely to spec as normally this should be
	// initialized in a manner analogous to how sequence numbers are
	// randomized per connection basis. But for now this is sufficient.
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// maybeEnableSACKPermitted marks the SACKPermitted option enabled for this endpoint
// if the SYN options indicate that the SACK option was negotiated and the TCP
// stack is configured to enable TCP SACK option.
func (e *endpoint) maybeEnableSACKPermitted(synOpts *header.TCPSynOptions) {
	var v SACKEnabled
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &v); err != nil {
		// Stack doesn't support SACK. So just return.
		return
	}
	if bool(v) && synOpts.SACKPermitted {
		e.sackPermitted = true
	}
}

// completeState makes a full copy of the endpoint and returns it. This is used
// before invoking the probe. The state returned may not be fully consistent if
// there are intervening syscalls when the state is being copied.
func (e *endpoint) completeState() stack.TCPEndpointState {
	var s stack.TCPEndpointState
	s.SegTime = time.Now()

	// Copy EndpointID.
	e.mu.Lock()
	s.ID = stack.TCPEndpointID(e.id)
	e.mu.Unlock()

	// Copy endpoint rcv state.
	e.rcvListMu.Lock()
	s.RcvBufSize = e.rcvBufSize
	s.RcvBufUsed = e.rcvBufUsed
	s.RcvClosed = e.rcvClosed
	e.rcvListMu.Unlock()

	// Endpoint TCP Option state.
	s.SendTSOk = e.sendTSOk
	s.RecentTS = e.recentTS
	s.TSOffset = e.tsOffset
	s.SACKPermitted = e.sackPermitted
	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])

	// Copy endpoint send state.
	e.sndBufMu.Lock()
	s.SndBufSize = e.sndBufSize
	s.SndBufUsed = e.sndBufUsed
	s.SndClosed = e.sndClosed
	s.SndBufInQueue = e.sndBufInQueue
	s.PacketTooBigCount = e.packetTooBigCount
	s.SndMTU = e.sndMTU
	e.sndBufMu.Unlock()

	// Copy receiver state.
	s.Receiver = stack.TCPReceiverState{
		RcvNxt:         e.rcv.rcvNxt,
		RcvAcc:         e.rcv.rcvAcc,
		RcvWndScale:    e.rcv.rcvWndScale,
		PendingBufUsed: e.rcv.pendingBufUsed,
		PendingBufSize: e.rcv.pendingBufSize,
	}

	// Copy sender state.
	s.Sender = stack.TCPSenderState{
		LastSendTime: e.snd.lastSendTime,
		DupAckCount:  e.snd.dupAckCount,
		//FastRecovery: stack.TCPFastRecoveryState{
		//	Active:  e.snd.fr.active,
		//	First:   e.snd.fr.first,
		//	Last:    e.snd.fr.last,
		//	MaxCwnd: e.snd.fr.maxCwnd,
		//},
		SndCwnd:          e.snd.sndCwnd,
		Ssthresh:         e.snd.sndSsthresh,
		SndCAAckCount:    e.snd.sndCAAckCount,
		Outstanding:      e.snd.outstanding,
		SndWnd:           e.snd.sndWnd,
		SndUna:           e.snd.sndUna,
		SndNxt:           e.snd.sndNxt,
		RTTMeasureSeqNum: e.snd.rttMeasureSeqNum,
		RTTMeasureTime:   e.snd.rttMeasureTime,
		Closed:           e.snd.closed,
		RTO:              e.snd.rto,
		SRTTInited:       e.snd.srttInited,
		MaxPayloadSize:   e.snd.maxPayloadSize,
		SndWndScale:      e.snd.sndWndScale,
		MaxSentAck:       e.snd.maxSentAck,
	}
	e.snd.rtt.Lock()
	s.Sender.SRTT = e.snd.rtt.srtt
	e.snd.rtt.Unlock()

	//if cubic, ok := e.snd.cc.(*cubicState); ok {
	//	s.Sender.Cubic = stack.TCPCubicState{
	//		WMax:                    cubic.wMax,
	//		WLastMax:                cubic.wLastMax,
	//		T:                       cubic.t,
	//		TimeSinceLastCongestion: time.Since(cubic.t),
	//		C:                       cubic.c,
	//		K:                       cubic.k,
	//		Beta:                    cubic.beta,
	//		WC:                      cubic.wC,
	//		WEst:                    cubic.wEst,
	//	}
	//}
	return s
}
