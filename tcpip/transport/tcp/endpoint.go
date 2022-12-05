package tcp

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
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
	id                stack.TransportEndpointID
	state             endpointState
	isPortReserved    bool
	isRegistered      bool
	boundNICID        tcpip.NICID
	route             stack.Route
	v6only            bool
	isConnectNotified bool
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

// Bind binds the endpoint to a specific local port and optionally address.
// 将端点绑定到特定的本地端口和可选的地址。
func (e *endpoint) Bind(address tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	log.Println("绑定一个tcp端口")

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
