package tcp

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
	"netstack/waiter"
	"sync"
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

// endpoint 表示TCP端点。该结构用作端点用户和协议实现之间的接口;让并发goroutine调用端点是合法的，
// 它们是正确同步的。然而，协议实现在单个goroutine中运行。
type endpoint struct {
	stack       *stack.Stack                // 网络协议栈
	netProto    tcpip.NetworkProtocolNumber // 网络协议号 ipv4 ipv6
	waiterQueue *waiter.Queue               // 事件驱动机制

	// TODO 需要添加

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

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// acceptedChan is used by a listening endpoint protocol goroutine to
	// send newly accepted connections to the endpoint so that they can be
	// read by Accept() calls.
	acceptedChan chan *endpoint

	// The following are only used to assist the restore run to re-connect.
	bindAddress       tcpip.Address
	connectingAddress tcpip.Address
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
	}
	// TODO 需要添加
	log.Println("新建tcp端")
	return e
}

func (e *endpoint) Close() {

}

func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	return nil, tcpip.ControlMessages{}, nil
}

func (e *endpoint) Write(tcpip.Payload, tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	return 0, nil, nil
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

func (e *endpoint) Connect(address tcpip.FullAddress) *tcpip.Error {
	return nil
}

func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	return nil
}

func (e *endpoint) Listen(backlog int) (err *tcpip.Error) {
	log.Println("监听一个tcp端口")
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
	// TODO tcp服务端实现的主循环，这个函数很重要，用一个goroutine来服务
	go e.protocolListenLoop(seqnum.Size(0))

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
	case n = <-e.acceptedChan:
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
	return waiter.EventErr
}

func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	return nil
}

func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	log.Println("接收到数据")
	s := newSegment(r, id, vv)
	// 解析tcp段，如果解析失败，丢弃该报文
	if !s.parse() {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		s.decRef()
		return
	}

	e.stack.Stats().TCP.ValidSegmentsReceived.Increment() // 有效报文喜加一
	log.Println(s)
}

func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {

}
