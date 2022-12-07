package tcp

import (
	"crypto/rand"
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
)

const maxSegmentsPerWake = 100

type handshakeState int

const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

// The following are used to set up sleepers.
const (
	wakerForNotification = iota
	wakerForNewSegment
	wakerForResend
	wakerForResolution
)

// handshake holds the state used during a TCP 3-way handshake.
// tcp三次握手时候使用的对象
type handshake struct {
	ep *endpoint
	// 握手的状态
	state  handshakeState
	active bool
	flags  uint8
	ackNum seqnum.Value

	// iss is the initial send sequence number, as defined in RFC 793.
	// 初始序列号
	iss seqnum.Value

	// rcvWnd is the receive window, as defined in RFC 793.
	// 接收窗口
	rcvWnd seqnum.Size

	// sndWnd is the send window, as defined in RFC 793.
	// 发送窗口
	sndWnd seqnum.Size

	// mss is the maximum segment size received from the peer.
	// 最大报文段大小
	mss uint16

	// sndWndScale is the send window scale, as defined in RFC 1323. A
	// negative value means no scaling is supported by the peer.
	// 发送窗口扩展因子
	sndWndScale int

	// rcvWndScale is the receive window scale, as defined in RFC 1323.
	// 接收窗口扩展因子
	rcvWndScale int
}

const (
	// Maximum space available for options.
	// tcp选项的最大长度
	maxOptionSize = 40
)

func newHandshake(ep *endpoint, rcvWnd seqnum.Size) (handshake, *tcpip.Error) {
	h := handshake{
		ep:     ep,
		active: true,   // 激活这个管理器
		rcvWnd: rcvWnd, // 初始接收窗口
		// TODO
	}
	if err := h.resetState(); err != nil {
		return handshake{}, err
	}
	return h, nil
}

func (h *handshake) resetState() *tcpip.Error {
	// 随机一个iss(对方将收到的序号) 防止黑客搞事
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// 初始化状态为 SynSent
	h.state = handshakeSynSent
	log.Println("收到 syn 同步报文 设置tcp状态为 [sent]")
	h.flags = flagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = seqnum.Value(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24)

	return nil
}

// resetToSynRcvd resets the state of the handshake object to the SYN-RCVD
// state.
func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value, opts *header.TCPSynOptions) {
	h.active = false
	h.state = handshakeSynRcvd
	log.Println("发送 syn|ack 确认报文 设置tcp状态为 [rcvd]")
	h.flags = flagSyn | flagAck
	h.iss = iss
	h.ackNum = irs + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
}

// execute executes the TCP 3-way handshake.
// 执行tcp 3次握手，客户端和服务端都是调用该函数来实现三次握手
/*
			c	   flag  	s
			|				|
   sync_sent|------sync---->|sync_rcvd
			|				|
			|				|
 established|<--sync|ack----|
			|				|
			|				|
			|------ack----->|established
*/
func (h *handshake) execute() *tcpip.Error {
	// sync报文的选项参数
	synOpts := header.TCPSynOptions{}
	// 如果是客户端发送 syn 报文，如果是服务端发送 syn+ack 报文
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
	return nil
}

// 封装 sendTCP ，发送 syn 报文
func sendSynTCP(r *stack.Route, id stack.TransportEndpointID, flags byte,
	seq, ack seqnum.Value, rcvWnd seqnum.Size, opts header.TCPSynOptions) *tcpip.Error {

	options := []byte{}
	err := sendTCP(r, id, buffer.VectorisedView{}, 0, flags, seq, ack, rcvWnd, options)

	return err
}

// sendTCP sends a TCP segment with the provided options via the provided
// network endpoint and under the provided identity.
// 发送一个tcp段数据，封装 tcp 首部，并写入网路层
func sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.VectorisedView, ttl uint8, flags byte,
	seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte) *tcpip.Error {
	log.Println("进行一个报文的发送")
	return nil
}

// protocolMainLoop 是TCP协议的主循环。它在自己的goroutine中运行，负责握手、发送段和处理收到的段
func (e *endpoint) protocolMainLoop(handshake bool) *tcpip.Error {
	for {
		log.Println("三次握手机制在这里实现")
		select {}
	}
}
