package tcp

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"log"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
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

	return n, nil
}

func (l *listenContext) createEndpointAndPerformHandshake(s *segment, opts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {
	// create new endpoint
	irs := s.sequenceNumber
	cookie := l.createCookie(s.id, irs, encodeMSS(opts.MSS))
	log.Println("收到一个远端握手申请", irs, "标记cookie", cookie)
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
	if err := h.execute(); err != nil {
		ep.Close()
		return nil, err
	}

	// TODO 更新接收窗口扩张因子

	return ep, nil
}

// 一旦侦听端点收到SYN段，handleSynSegment就会在其自己的goroutine中调用。它负责完成握手并将新端点排队以进行接受。
// 在TCP开始使用SYN cookie接受连接之前，允许使用有限数量的这些goroutine。
func (e *endpoint) handleSynSegment(ctx *listenContext, s *segment, opts *header.TCPSynOptions) {
	defer decSynRcvdCount()
	defer s.decRef()

	_, err := ctx.createEndpointAndPerformHandshake(s, opts)
	if err != nil {
		return
	}
	// 到这里，三次握手已经完成，那么分发一个新的连接
	//e.deliverAccepted(n)
}

// handleListenSegment is called when a listening endpoint receives a segment
// and needs to handle it.
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) {
	switch s.flags {
	case flagSyn: // syn报文处理
		// 分析tcp选项
		opts := parseSynSegmentOptions(s)
		if incSynRcvdCount() {
			s.incRef()
			go e.handleSynSegment(ctx, s, &opts)
		} else {
			cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
			// Send SYN with window scaling because we currently
			// dont't encode this information in the cookie.
			//
			// Enable Timestamp option if the original syn did have
			// the timestamp option specified.
			synOpts := header.TCPSynOptions{
				WS:    -1,
				TS:    opts.TS,
				TSVal: tcpTimeStamp(timeStampOffset()),
				TSEcr: opts.TSVal,
			}
			// 返回 syn+ack 报文
			sendSynTCP(&s.route, s.id, flagSyn|flagAck, cookie, s.sequenceNumber+1, ctx.rcvWnd, synOpts)
		}
	// 返回一个syn+ack报文
	case flagFin: // fin报文处理
		// 三次握手最后一次 ack 报文
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
		// TODO 后置处理
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
			log.Println("你是一个一个新连接")
			mayRequeue := true
			// 接收和处理tcp报文
			for i := 0; i < maxSegmentsPerWake; i++ {
				s := e.segmentQueue.dequeue()
				if s == nil {
					mayRequeue = false
					break
				}
				e.handleListenSegment(ctx, s)
				s.decRef()
			}
			// If the queue is not empty, make sure we'll wake up
			// in the next iteration.
			if mayRequeue && !e.segmentQueue.empty() { // 主协程又添加了新数据
				e.newSegmentWaker.Assert() // 重新尝试获取数据
			}
		case wakerForNotification:
			// TODO 触发其他事件
			log.Println("其他事件?")
		default:
			panic((nil))
		}
	}
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
