package udp

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/stack"
	"netstack/waiter"
	"sync"
)

// udp报文结构 当收到udp报文时 会用这个结构来保存udp报文数据
type udpPacker struct {
	// TODO 需要添加
}

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
	mu sync.RWMutex
	// TODO 需要添加
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber,
	waiterQueue *waiter.Queue) *endpoint {
	log.Println("新建传输层实现")
	return &endpoint{}
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

// Bind binds the endpoint to a specific local address and port.
// Specifying a NIC is optional.
// Bind 将该UDP端绑定本地的一个IP+端口
// 例如：绑定本地0.0.0.0的9000端口，那么其他机器给这台机器9000端口发消息，该UDP端就能收到消息了
func (e *endpoint) Bind(address tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	log.Println("绑定端口", address)
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
