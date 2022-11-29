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
	// TODO 需要添加
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
	rcvTimestamp  bool

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

	// TODO

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address). 当前生效的网络层协议
	effectiveNetProtos []tcpip.NetworkProtocolNumber
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber,
	waiterQueue *waiter.Queue) *endpoint {
	log.Println("新建一个udp端")
	return &endpoint{
		stack:         stack,
		netProto:      netProto,
		waiterQueue:   waiterQueue,
		multicastTTL:  1,
		rcvBufSizeMax: 32 * 1024,
		sndBufSize:    32 * 1024}
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

func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	return nil, tcpip.ControlMessages{}, nil
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

func (e *endpoint) Connect(address tcpip.FullAddress) *tcpip.Error {
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
	err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e)
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

// 从网络层接收到UDP数据报时的处理函数
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {

}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
}
