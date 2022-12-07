package tcp

import (
	"crypto/rand"
	"fmt"
	"log"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
	"sync"
	"time"
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
	h.ackNum = irs + 1 // NOTE ACK = synNum + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
}

func (h *handshake) resolveRoute() *tcpip.Error {
	log.Printf("tcp resolveRoute")
	// Set up the wakers.
	s := sleep.Sleeper{}
	resolutionWaker := &sleep.Waker{}
	s.AddWaker(resolutionWaker, wakerForResolution)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	defer s.Done()

	// Initial action is to resolve route.
	index := wakerForResolution
	for {
		log.Println(index)
		switch index {
		case wakerForResolution:
			if _, err := h.ep.route.Resolve(resolutionWaker); err != tcpip.ErrWouldBlock {
				// Either success (err == nil) or failure.
				return err
			}
			// Resolution not completed. Keep trying...

		case wakerForNotification:
			// TODO
			//n := h.ep.fetchNotifications()
			//if n&notifyClose != 0 {
			//	h.ep.route.RemoveWaker(resolutionWaker)
			//	return tcpip.ErrAborted
			//}
			//if n&notifyDrain != 0 {
			//	close(h.ep.drainDone)
			//	<-h.ep.undrain
			//}
		}

		// Wait for notification.
		index, _ = s.Fetch(true)
	}
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
	// 是否需要拿到下一条地址
	if h.ep.route.IsResolutionRequired() {
		if err := h.resolveRoute(); err != nil {
			return err
		}
	}
	// Initialize the resend timer.
	// 初始化重传定时器
	resendWaker := sleep.Waker{}
	// 设置1s超时
	timeOut := time.Duration(time.Second)
	rt := time.AfterFunc(timeOut, func() {
		resendWaker.Assert()
	})
	defer rt.Stop()

	// Set up the wakers.
	s := sleep.Sleeper{}
	s.AddWaker(&resendWaker, wakerForResend)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	s.AddWaker(&h.ep.newSegmentWaker, wakerForNewSegment)
	defer s.Done()

	// sync报文的选项参数
	synOpts := header.TCPSynOptions{}
	// 如果是客户端发送 syn 报文，如果是服务端发送 syn+ack 报文
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

	for h.state != handshakeCompleted {
		// 获取事件id
		switch index, _ := s.Fetch(true); index {
		case wakerForResend: // NOTE tcp超时重传机制
			// 如果是客户端当发送 syn 报文，超过一定的时间未收到回包，触发超时重传
			// 如果是服务端当发送 syn+ack 报文，超过一定的时间未收到 ack 回包，触发超时重传
			// 超时时间变为上次的2倍
			timeOut *= 2
			if timeOut > 60*time.Second {
				return tcpip.ErrTimeout
			}
			rt.Reset(timeOut)
			// 重新发送syn报文
			sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

		case wakerForNotification:

		case wakerForNewSegment:
			// 处理握手报文
		}
	}
	return nil
}

var optionPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxOptionSize)
	},
}

// 减少资源浪费
func getOptions() []byte {
	return optionPool.Get().([]byte)
}

func putOptions(options []byte) {
	// Reslice to full capacity.
	optionPool.Put(options[0:cap(options)])
}

// tcp选项的编码 将一个TCPSyncOptions编码到 []byte 中
func makeSynOptions(opts header.TCPSynOptions) []byte {
	// Emulate linux option order. This is as follows:
	//
	// if md5: NOP NOP MD5SIG 18 md5sig(16)
	// if mss: MSS 4 mss(2)
	// if ts and sack_advertise:
	//	SACK 2 TIMESTAMP 2 timestamp(8)
	// elif ts: NOP NOP TIMESTAMP 10 timestamp(8)
	// elif sack: NOP NOP SACK 2
	// if wscale: NOP WINDOW 3 ws(1)
	// if sack_blocks: NOP NOP SACK ((2 + (#blocks * 8))
	//	[for each block] start_seq(4) end_seq(4)
	// if fastopen_cookie:
	//	if exp: EXP (4 + len(cookie)) FASTOPEN_MAGIC(2)
	// 	else: FASTOPEN (2 + len(cookie))
	//	cookie(variable) [padding to four bytes]
	//
	options := getOptions()

	// Always encode the mss.
	offset := header.EncodeMSSOption(uint32(opts.MSS), options)

	// Special ordering is required here. If both TS and SACK are enabled,
	// then the SACK option precedes TS, with no padding. If they are
	// enabled individually, then we see padding before the option.
	if opts.TS && opts.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.TS {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.SACKPermitted {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKPermittedOption(options[offset:])
	}

	// Initialize the WS option.
	if opts.WS >= 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeWSOption(opts.WS, options[offset:])
	}

	// Padding to the end; note that this never apply unless we add a
	// fastopen option, we always expect the offset to remain the same.
	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

// 封装 sendTCP ，发送 syn 报文
func sendSynTCP(r *stack.Route, id stack.TransportEndpointID, flags byte,
	seq, ack seqnum.Value, rcvWnd seqnum.Size, opts header.TCPSynOptions) *tcpip.Error {
	if opts.MSS == 0 {
		opts.MSS = uint16(r.MTU() - header.TCPMinimumSize)
	}
	options := makeSynOptions(opts)
	err := sendTCP(r, id, buffer.VectorisedView{}, r.DefaultTTL(), flags, seq, ack, rcvWnd, options)
	return err
}

// sendTCP sends a TCP segment with the provided options via the provided
// network endpoint and under the provided identity.
// 发送一个tcp段数据，封装 tcp 首部，并写入网路层
func sendTCP(r *stack.Route, id stack.TransportEndpointID, data buffer.VectorisedView, ttl uint8, flags byte,
	seq, ack seqnum.Value, rcvWnd seqnum.Size, opts []byte) *tcpip.Error {
	log.Println("进行一个报文的发送")
	optLen := len(opts)
	// Allocate a buffer for the TCP header.
	hdr := buffer.NewPrependable(header.TCPMinimumSize + int(r.MaxHeaderLength()) + optLen)

	if rcvWnd > 0xffff {
		rcvWnd = 0xffff
	}

	// Initialize the header.
	tcp := header.TCP(hdr.Prepend(header.TCPMinimumSize + optLen))
	tcp.Encode(&header.TCPFields{
		SrcPort:    id.LocalPort,
		DstPort:    id.RemotePort,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      flags,
		WindowSize: uint16(rcvWnd),
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	// Only calculate the checksum if offloading isn't supported.
	if r.Capabilities()&stack.CapabilityChecksumOffload == 0 {
		length := uint16(hdr.UsedLength() + data.Size())
		// tcp伪首部校验和的计算
		xsum := r.PseudoHeaderChecksum(ProtocolNumber)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}

		// tcp的可靠性：校验和的计算，用于检测损伤的报文段
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum, length))
	}

	r.Stats().TCP.SegmentsSent.Increment()
	if (flags & flagRst) != 0 {
		r.Stats().TCP.ResetsSent.Increment()
	}

	log.Printf("send tcp %s segment to %s, seq: %d, ack: %d, rcvWnd: %d",
		flagString(flags), fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort),
		seq, ack, rcvWnd)

	return r.WritePacket(hdr, data, ProtocolNumber, ttl)
}

// protocolMainLoop 是TCP协议的主循环。它在自己的goroutine中运行，负责握手、发送段和处理收到的段
func (e *endpoint) protocolMainLoop(handshake bool) *tcpip.Error {
	for {
		log.Println("三次握手机制在这里实现")
		select {}
	}
}
