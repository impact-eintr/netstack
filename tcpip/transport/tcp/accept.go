package tcp

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"log"
	"netstack/logger"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
	"netstack/waiter"
	"sync"
	"time"
)

const (
	// tsLen is the length, in bits, of the timestamp in the SYN cookie.
	tsLen = 8

	// tsMask is a mask for timestamp values (i.e., tsLen bits).
	tsMask = (1 << tsLen) - 1

	// tsOffset is the offset, in bits, of the timestamp in the SYN cookie.
	tsOffset = 24

	// hashMask is the mask for hash values (i.e., tsOffset bits).
	hashMask = (1 << tsOffset) - 1

	// maxTSDiff is the maximum allowed difference between a received cookie
	// timestamp and the current timestamp. If the difference is greater
	// than maxTSDiff, the cookie is expired.
	maxTSDiff = 2
)

var (
	// SynRcvdCountThreshold is the global maximum number of connections
	// that are allowed to be in SYN-RCVD state before TCP starts using SYN
	// cookies to accept connections.
	//
	// It is an exported variable only for testing, and should not otherwise
	// be used by importers of this package.
	SynRcvdCountThreshold uint64 = 1000

	// mssTable is a slice containing the possible MSS values that we
	// encode in the SYN cookie with two bits.
	mssTable = []uint16{536, 1300, 1440, 1460}
)

func encodeMSS(mss uint16) uint32 {
	for i := len(mssTable) - 1; i > 0; i-- {
		if mss >= mssTable[i] {
			return uint32(i)
		}
	}
	return 0
}

// syncRcvdCount is the number of endpoints in the SYN-RCVD state. The value is
// protected by a mutex so that we can increment only when it's guaranteed not
// to go above a threshold.
var synRcvdCount struct {
	sync.Mutex
	value   uint64
	pending sync.WaitGroup
}

// listenContext is used by a listening endpoint to store state used while
// listening for connections. This struct is allocated by the listen goroutine
// and must not be accessed or have its methods called concurrently as they
// may mutate the stored objects.
type listenContext struct {
	stack  *stack.Stack
	rcvWnd seqnum.Size
	nonce  [2][sha1.BlockSize]byte // nonce 随机数

	hasherMu sync.Mutex
	hasher   hash.Hash // 散列实现
	v6only   bool
	netProto tcpip.NetworkProtocolNumber
}

// timeStamp returns an 8-bit timestamp with a granularity of 64 seconds.
func timeStamp() uint32 {
	return uint32(time.Now().Unix()>>6) & tsMask // 00 00 00 FF
}

// 增加一个任务 最多1000个
func incSynRcvdCount() bool {
	synRcvdCount.Mutex.Lock()
	defer synRcvdCount.Unlock()

	if synRcvdCount.value >= SynRcvdCountThreshold {
		return false
	}

	synRcvdCount.pending.Add(1)
	synRcvdCount.value++
	return true
}

// 结束一个任务
func decSynRcvdCount() {
	synRcvdCount.Mutex.Lock()
	defer synRcvdCount.Unlock()
	synRcvdCount.value--
	synRcvdCount.pending.Done()
}

// newListenContext creates a new listen context.
func newListenContext(stack *stack.Stack, rcvWnd seqnum.Size, v6only bool, netProto tcpip.NetworkProtocolNumber) *listenContext {
	l := &listenContext{
		stack:    stack,
		rcvWnd:   rcvWnd,
		hasher:   sha1.New(),
		v6only:   v6only,
		netProto: netProto,
	}

	rand.Read(l.nonce[0][:])
	rand.Read(l.nonce[1][:])

	return l
}

// cookieHash calculates the cookieHash for the given id, timestamp and nonce
// index. The hash is used to create and validate cookies.
func (l *listenContext) cookieHash(id stack.TransportEndpointID, ts uint32, nonceIndex int) uint32 {

	// Initialize block with fixed-size data: local ports and v.
	var payload [8]byte
	binary.BigEndian.PutUint16(payload[0:], id.LocalPort)
	binary.BigEndian.PutUint16(payload[2:], id.RemotePort)
	binary.BigEndian.PutUint32(payload[4:], ts)

	// Feed everything to the hasher.
	l.hasherMu.Lock()
	l.hasher.Reset()
	l.hasher.Write(payload[:])
	l.hasher.Write(l.nonce[nonceIndex][:])
	io.WriteString(l.hasher, string(id.LocalAddress))
	io.WriteString(l.hasher, string(id.RemoteAddress))

	// Finalize the calculation of the hash and return the first 4 bytes.
	h := make([]byte, 0, sha1.Size)
	h = l.hasher.Sum(h)
	l.hasherMu.Unlock()

	return binary.BigEndian.Uint32(h[:])
}

// createCookie creates a SYN cookie for the given id and incoming sequence
// number.
func (l *listenContext) createCookie(id stack.TransportEndpointID,
	seq seqnum.Value, data uint32) seqnum.Value {
	ts := timeStamp()
	v := l.cookieHash(id, 0, 0) + uint32(seq) + (ts << tsOffset)
	v += (l.cookieHash(id, ts, 1) + data) & hashMask
	return seqnum.Value(v)
}

// isCookieValid checks if the supplied cookie is valid for the given id and
// sequence number. If it is, it also returns the data originally encoded in the
// cookie when createCookie was called.
func (l *listenContext) isCookieValid(id stack.TransportEndpointID,
	cookie seqnum.Value, seq seqnum.Value) (uint32, bool) {
	ts := timeStamp()
	v := uint32(cookie) - l.cookieHash(id, 0, 0) - uint32(seq)
	cookieTS := v >> tsOffset
	if ((ts - cookieTS) & tsMask) > maxTSDiff {
		return 0, false
	}

	return (v - l.cookieHash(id, cookieTS, 1)) & hashMask, true
}

// 新建一个tcp端 这个tcp端与segment同属一个tcp连接 但属于不同阶段 用于写回远端
func (l *listenContext) createConnectedEndpoint(s *segment, iss seqnum.Value,
	irs seqnum.Value, rcvdSynOpts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {
	// Create a new endpoint.
	netProto := l.netProto
	if netProto == 0 {
		netProto = s.route.NetProto
	}
	n := newEndpoint(l.stack, netProto, nil)
	n.v6only = l.v6only
	n.id = s.id
	n.boundNICID = s.route.NICID()
	n.route = s.route.Clone()
	n.effectiveNetProtos = []tcpip.NetworkProtocolNumber{s.route.NetProto}
	n.rcvBufSize = int(l.rcvWnd)

	n.maybeEnableTimestamp(rcvdSynOpts)
	n.maybeEnableSACKPermitted(rcvdSynOpts)

	// Register new endpoint so that packets are routed to it.
	// 在网络协议栈中去注册这个tcp端
	if err := n.stack.RegisterTransportEndpoint(n.boundNICID,
		n.effectiveNetProtos, ProtocolNumber, n.id, n); err != nil {
		n.Close()
		return nil, err
	}

	n.isRegistered = true
	n.state = stateConnected

	// Create sender and receiver.
	// The receiver at least temporarily has a zero receive window scale,
	// but the caller may change it (before starting the protocol loop).
	n.snd = newSender(n, iss, irs, s.window, rcvdSynOpts.MSS, rcvdSynOpts.WS)
	n.rcv = newReceiver(n, irs, l.rcvWnd, 0)
	logger.GetInstance().Info(logger.HANDSHAKE, func() {
		log.Println("服务端握手成功 服务端的recver", n.rcv)
	})

	return n, nil
}

func (l *listenContext) createEndpointAndPerformHandshake(s *segment, opts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {
	// create new endpoint
	irs := s.sequenceNumber
	cookie := l.createCookie(s.id, irs, encodeMSS(opts.MSS))
	logger.GetInstance().Info(logger.HANDSHAKE, func() {
		log.Println("收到一个远端握手申请 SYN seq =", irs, "客户端请携带 标记 iss ", cookie, "+1")
	})
	ep, err := l.createConnectedEndpoint(s, cookie, irs, opts)
	if err != nil {
		return nil, err
	}

	// 以下执行三次握手

	// 构建handshake管理器
	h, err := newHandshake(ep, l.rcvWnd)
	if err != nil {
		ep.Close()
		return nil, err
	}
	// 标记状态为 handshakeSynRcvd 和 h.flags为 syn+ack
	h.resetToSynRcvd(cookie, irs, opts)

	log.Println("TCP STATE SYN_RCVD")

	// 发送ack报文 接收client返回的ack
	if err := h.execute(); err != nil {
		ep.Close()
		return nil, err
	}

	// 更新接收窗口扩张因子
	ep.rcv.rcvWndScale = h.effectiveRcvWndScale()

	return ep, nil
}

func (e *endpoint) deliverAccepted(n *endpoint) {
	e.mu.RLock()
	if e.state == stateListen {
		e.acceptedChan <- n
		e.waiterQueue.Notify(waiter.EventIn) // 通知 Accept() 停止阻塞
	} else {
		n.Close()
	}
	e.mu.RUnlock()
}

// 一旦侦听端点收到SYN段，handleSynSegment就会在其自己的goroutine中调用。它负责完成握手并将新端点排队以进行接受。
// 在TCP开始使用SYN cookie接受连接之前，允许使用有限数量的这些goroutine。
func (e *endpoint) handleSynSegment(ctx *listenContext, s *segment, opts *header.TCPSynOptions) {
	defer decSynRcvdCount()
	defer s.decRef()

	// 这里返回的 n 是一个新的tcp端: LAddr:Port+RAddr:RPort
	n, err := ctx.createEndpointAndPerformHandshake(s, opts)
	if err != nil {
		return
	}
	// 到这里，三次握手已经完成，那么分发一个新的连接
	e.deliverAccepted(n) // 分发这个新连接到全连接队列
}

// handleListenSegment is called when a listening endpoint receives a segment
// and needs to handle it.
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) {
	switch s.flags {
	case flagSyn: // syn报文处理
		// 分析tcp选项
		opts := parseSynSegmentOptions(s)
		if !incSynRcvdCount() {
			s.incRef()
			go e.handleSynSegment(ctx, s, &opts)
		} else {
			// 防止半连接池攻击 我们使用cookie
			cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
			synOpts := header.TCPSynOptions{
				WS:    -1, // 告知对方关闭窗口滑动
				TS:    opts.TS,
				TSVal: tcpTimeStamp(timeStampOffset()),
				TSEcr: opts.TSVal,
			}
			// 返回 syn+ack 报文 ack+1 表明我们确认了这个syn报文 占用一个字节
			sendSynTCP(&s.route, s.id, flagSyn|flagAck, cookie, s.sequenceNumber+1, ctx.rcvWnd, synOpts)
		}

	case flagAck:
		// NOTICE  对应处理后台协程过多的情况  三次握手最后一次 ack 报文
		// 当我们的后台写协程不足以处理新的连接的时候
		// 我们认为协议栈目前没有能力处理大规模数据
		// 所以我们限制后面新成立的连接的窗口尺寸

		// 验证cookie seq-1 和 ack-1 表明 还原两次握手增加的计数
		if data, ok := ctx.isCookieValid(s.id, s.ackNumber-1,
			s.sequenceNumber-1); ok && int(data) < len(mssTable) {
			// Create newly accepted endpoint and deliver it.
			rcvdSynOptions := &header.TCPSynOptions{
				MSS: mssTable[data],
				// 关闭我们的窗口滑动
				WS: -1,
			}
			if s.parsedOptions.TS {
				rcvdSynOptions.TS = true
				rcvdSynOptions.TSVal = s.parsedOptions.TSVal
				rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
			}

			// 三次握手已经完成，新建一个tcp连接
			n, err := ctx.createConnectedEndpoint(s, s.ackNumber-1,
				s.sequenceNumber-1, rcvdSynOptions)
			if err == nil {
				n.tsOffset = 0
				e.deliverAccepted(n) // 分发这个新连接到全连接队列
			}
		}
	}
}

func parseSynSegmentOptions(s *segment) header.TCPSynOptions {
	synOpts := header.ParseSynOptions(s.options, s.flagIsSet(flagAck))
	if synOpts.TS {
		s.parsedOptions.TSVal = synOpts.TSVal
		s.parsedOptions.TSEcr = synOpts.TSEcr
	}
	return synOpts
}

// protocolListenLoop 是侦听TCP端点的主循环。它在自己的goroutine中运行，负责处理连接请求
// 什么叫处理连接请求呢 其实就是 ep.Listen()时在协议栈中注册了一个Laddr+LPort的组合
// 当有客户端给服务端发送 syn 报文时 由于是新连接 所以服务端并没有相关信息
// 服务端会把这个报文交给 LAddr:LPort 的ep 去处理 也就是以下Loop
// 在验证通过后 会新建并注册一个 LAddr:LPort+RAddr:RPort的新ep 由它来处理后续的请求
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) *tcpip.Error {
	defer func() {
		e.mu.Lock()
		e.state = stateClosed

		// Do cleanup if needed.
		e.completeWorkerLocked()

		//if e.drainDone != nil {
		//	close(e.drainDone)
		//}
		e.mu.Unlock()

		// Notify waiters that the endpoint is shutdown.
		e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut)
	}()

	e.mu.Lock()
	v6only := e.v6only
	e.mu.Unlock()
	ctx := newListenContext(e.stack, rcvWnd, v6only, e.netProto)
	// 初始化事件触发器 并添加事件
	s := sleep.Sleeper{}
	s.AddWaker(&e.newSegmentWaker, wakerForNewSegment)
	s.AddWaker(&e.notificationWaker, wakerForNotification)

	for {
		var index int
		switch index, _ = s.Fetch(true); index { // Fetch(true) 阻塞获取
		case wakerForNewSegment:
			mayRequeue := true
			// 接收和处理tcp报文
			for i := 0; i < maxSegmentsPerWake; i++ {
				s := e.segmentQueue.dequeue()
				if s == nil {
					mayRequeue = false
					break
				}
				log.Println("TCP STATE LISTEN")
				e.handleListenSegment(ctx, s)
				s.decRef()
			}
			// If the queue is not empty, make sure we'll wake up
			// in the next iteration.
			if mayRequeue && !e.segmentQueue.empty() { // 主协程又添加了新数据
				e.newSegmentWaker.Assert() // 重新尝试获取数据
			}
		case wakerForNotification:
			n := e.fetchNotifications()
			if n&notifyClose != 0 {
				return nil
			}
		default:
			panic((nil))
		}
	}
}
