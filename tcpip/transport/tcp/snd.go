package tcp

import (
	"fmt"
	"log"
	"math"
	"netstack/logger"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"sync"
	"time"
)

const (
	// minRTO is the minimum allowed value for the retransmit timeout.
	minRTO = 200 * time.Millisecond

	// InitialCwnd is the initial congestion window.
	// 初始拥塞窗口大小
	InitialCwnd = 10

	// nDupAckThreshold is the number of duplicate ACK's required
	// before fast-retransmit is entered.
	nDupAckThreshold = 3
)

// NOTE 这里实现了tcp的拥塞控制 很重要

// congestionControl is an interface that must be implemented by any supported
// congestion control algorithm.
// tcp拥塞控制：拥塞控制算法的接口
type congestionControl interface {
	// HandleNDupAcks is invoked when sender.dupAckCount >= nDupAckThreshold
	// just before entering fast retransmit.
	// 在进入快速重新传输之前，当 sender.dupAckCount> = nDupAckThreshold 时调用HandleNDupAcks。
	HandleNDupAcks()

	// HandleRTOExpired is invoked when the retransmit timer expires.
	// 当重新传输计时器到期时调用HandleRTOExpired。
	HandleRTOExpired()

	// Update is invoked when processing inbound acks. It's passed the
	// number of packet's that were acked by the most recent cumulative
	// acknowledgement.
	// 已经有数据包被确认时调用 Update。它传递了最近累积确认所确认的数据包数。
	Update(packetsAcked int)

	// PostRecovery is invoked when the sender is exiting a fast retransmit/
	// recovery phase. This provides congestion control algorithms a way
	// to adjust their state when exiting recovery.
	// 当发送方退出快速重新传输/恢复阶段时，将调用PostRecovery。
	// 这为拥塞控制算法提供了一种在退出恢复时调整其状态的方法。
	PostRecovery()
}

/*
                     +-------> sndWnd <-------+
                     |                        |
---------------------+-------------+----------+--------------------
|      acked         | * * * * * * | # # # # #|   unable send
---------------------+-------------+----------+--------------------
                     ^             ^
                     |             |
                   sndUna        sndNxt
***** in flight data
##### able send date
*/

// tcp发送器，它维护了tcp必要的状态
type sender struct {
	ep *endpoint

	// lastSendTime is the timestamp when the last packet was sent.
	// lastSendTime 是发送最后一个数据包的时间戳。
	lastSendTime time.Time

	// dupAckCount is the number of duplicated acks received. It is used for
	// fast retransmit.
	// dupAckCount 是收到的重复ack数。它用于快速重传。
	dupAckCount int

	// fr holds state related to fast recovery.
	// fr 持有与快速恢复有关的状态。
	fr fastRecovery

	// sndCwnd is the congestion window, in packets.
	// sndCwnd 是拥塞窗口，单位是包
	sndCwnd int

	// sndSsthresh is the threshold between slow start and congestion
	// avoidance.
	// sndSsthresh 是慢启动和拥塞避免之间的阈值。
	sndSsthresh int

	// sndCAAckCount is the number of packets acknowledged during congestion
	// avoidance. When enough packets have been ack'd (typically cwnd
	// packets), the congestion window is incremented by one.
	// sndCAAckCount 是拥塞避免期间确认的数据包数。当已经确认了足够的分组（通常是cwnd分组）时，拥塞窗口增加1。
	sndCAAckCount int

	// outstanding is the number of outstanding packets, that is, packets
	// that have been sent but not yet acknowledged.
	// outstanding 是正在发送的数据包的数量，即已发送但尚未确认的数据包。
	outstanding int

	// sndWnd is the send window size.
	// 发送窗口大小，单位是字节
	sndWnd seqnum.Size

	// sndUna is the next unacknowledged sequence number.
	// sndUna 是下一个未确认的序列号
	sndUna seqnum.Value

	/*
			数据流 	下一个将要被缓存的数据          队列指针
		[...xxxxxxxx] => sndNxtList<-->[tail       sndUna       sndNxt] ---> NIC<--->NIC
									                          缓存队列头
	*/

	// sndNxt 是要发送的下一个段的序列号。
	sndNxt seqnum.Value

	// sndNxtList is the sequence number of the next segment to be added to
	// the send list.
	// sndNxtList 是要添加到发送列表的下一个段的序列号。
	sndNxtList seqnum.Value

	// rttMeasureSeqNum is the sequence number being used for the latest RTT
	// measurement.
	rttMeasureSeqNum seqnum.Value

	// rttMeasureTime is the time when the rttMeasureSeqNum was sent.
	rttMeasureTime time.Time

	closed    bool
	writeNext *segment
	// 发送链表
	writeList   segmentList
	resendTimer timer
	resendWaker sleep.Waker

	rtt        rtt           // 往返时间
	rto        time.Duration // 超时重发时间
	srttInited bool

	// maxPayloadSize is the maximum size of the payload of a given segment.
	// It is initialized on demand.
	maxPayloadSize int

	// sndWndScale is the number of bits to shift left when reading the send
	// window size from a segment.
	sndWndScale uint8

	// maxSentAck is the maxium acknowledgement actually sent.
	// 接收缓存中已经确认过的最小值 如果接收队列的所有数据均已确认 就更新发送队列的这个值
	/*
			                                         +------>    983041 <-----+
		                                             |                        |
		-----------------+-------------+-------------+------------------------+
		| ANR      65535 | not revived |  rcvd unack |   able rcv             |
		-----------------+-------------+-------------+------------------------+
		^                                            ^                        ^
		|                                            |                        |
		4146768523                               maxSendAck              4147817099
	*/
	maxSentAck seqnum.Value

	// cc is the congestion control algorithm in use for this sender.
	// cc 是实现拥塞控制算法的接口
	cc congestionControl
}

type rtt struct {
	sync.Mutex
	srtt   time.Duration // 平滑 RTT 时间
	rttvar time.Duration // rtt 平均偏差 ∑|x-xbar|/n
}

// fastRecovery holds information related to fast recovery from a packet loss.
//
// +stateify savable
// fastRecovery 保存与数据包丢失快速恢复相关的信息
type fastRecovery struct {
	active bool
	// TODO 需要解释
	first seqnum.Value
	last seqnum.Value

	maxCwnd int
}

// 新建并初始化发送器 irs是cookies
func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	s := &sender{
		ep:             ep,
		sndCwnd:        InitialCwnd, // TODO 暂时写死 tcp拥塞窗口 决定了发送窗口的初始大小
		sndSsthresh:    math.MaxInt64,
		sndWnd:         sndWnd,
		sndUna:         iss + 1,
		sndNxt:         iss + 1, // 缓存长度为0
		sndNxtList:     iss + 1,
		rto:            1 * time.Second,
		lastSendTime:   time.Now(),
		maxPayloadSize: int(mss),
		maxSentAck:     irs + 1,
	}
	// 拥塞控制算法的初始化
	s.cc = s.initCongestionControl(ep.cc)

	// A negative sndWndScale means that no scaling is in use, otherwise we
	// store the scaling value.
	if sndWndScale > 0 {
		s.sndWndScale = uint8(sndWndScale)
	}

	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)

	s.resendTimer.init(&s.resendWaker)

	return s
}

// tcp拥塞控制：根据算法名，新建拥塞控制算法和初始化
func (s *sender) initCongestionControl(congestionControlName CongestionControlOption) congestionControl {
	switch congestionControlName {
	//case ccCubic:
	//return newCubicCC(s)
	case ccReno:
		fallthrough
	default:
		return newRenoCC(s)
	}
}

// updateMaxPayloadSize updates the maximum payload size based on the given
// MTU. If this is in response to "packet too big" control packets (indicated
// by the count argument), it also reduces the number of outstanding packets and
// attempts to retransmit the first packet above the MTU size.
func (s *sender) updateMaxPayloadSize(mtu, count int) {
	m := mtu - header.TCPMinimumSize

	// Calculate the maximum option size.
	// 计算MSS的大小
	var maxSackBlocks [header.TCPMaxSACKBlocks]header.SACKBlock
	options := s.ep.makeOptions(maxSackBlocks[:])
	m -= len(options)
	putOptions(options)
	// We don't adjust up for now.
	if m >= s.maxPayloadSize {
		return
	}

	// Make sure we can transmit at least one byte.
	if m <= 0 {
		m = 1
	}

	s.maxPayloadSize = m
	s.outstanding -= count
	if s.outstanding < 0 {
		s.outstanding = 0
	}

	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		log.Fatal("计算MSS ", m, s.maxPayloadSize, s.outstanding)
		if seg == s.writeNext {
			// We got to writeNext before we could find a segment
			// exceeding the MTU.
			break
		}

		if seg.data.Size() > m {
			// We found a segment exceeding the MTU. Rewind
			// writeNext and try to retransmit it.
			s.writeNext = seg
			break
		}
	}

	// Since we likely reduced the number of outstanding packets, we may be
	// ready to send some more.
	s.sendData()
}

func (s *sender) sendAck() {
	s.sendSegment(buffer.VectorisedView{}, flagAck, s.sndNxt) // seq = cookies+1 ack ack|fin.seq+1
}

// updateRTO 根据rtt来更新计算rto
/*
第一次rtt计算：
SRTT = R
RTTVAR = R/2
RTO = SRTT + max (G, K*RTTVAR) = R + max(G, 2 * R)
K = 4

之后：
RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'| = 0.75 * RTTVAR + 0.25 * |SRTT - R'|
SRTT = (1 - alpha) * SRTT + alpha * R' = 0.875 * SRTT + 0.125 * R'
RTO = SRTT + max (G, K*RTTVAR) = SRTT + max(G, 4 * RTTVAR)
K = 4
*/
func (s *sender) updateRTO(rtt time.Duration) {
	s.rtt.Lock()
	// 第一次计算
	if !s.srttInited {
		s.rtt.srtt = rtt
		s.rtt.rttvar = rtt / 2
		s.srttInited = true
	} else {
		// |rtt-srtt| 标准差
		diff := s.rtt.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		if !s.ep.sendTSOk {
			s.rtt.rttvar = (3*s.rtt.rttvar + diff) / 4
			s.rtt.srtt = (7*s.rtt.srtt + rtt) / 8
		} else {
			// When we are taking RTT measurements of every ACK then
			// we need to use a modified method as specified in
			// https://tools.ietf.org/html/rfc7323#appendix-G
			if s.outstanding == 0 {
				s.rtt.Unlock()
				return
			}
			// Netstack measures congestion window/inflight all in
			// terms of packets and not bytes. This is similar to
			// how linux also does cwnd and inflight. In practice
			// this approximation works as expected.
			expectedSamples := math.Ceil(float64(s.outstanding) / 2)

			// alpha & beta values are the original values as recommended in
			// https://tools.ietf.org/html/rfc6298#section-2.3.
			const alpha = 0.125
			const beta = 0.25

			alphaPrime := alpha / expectedSamples
			betaPrime := beta / expectedSamples
			rttVar := (1-betaPrime)*s.rtt.rttvar.Seconds() + betaPrime*diff.Seconds()
			srtt := (1-alphaPrime)*s.rtt.srtt.Seconds() + alphaPrime*rtt.Seconds()
			s.rtt.rttvar = time.Duration(rttVar * float64(time.Second))
			s.rtt.srtt = time.Duration(srtt * float64(time.Second))
		}
	}

	s.rto = s.rtt.srtt + 4*s.rtt.rttvar
	s.rtt.Unlock()
	if s.rto < minRTO {
		s.rto = minRTO
	}
	logger.NOTICE("更新RTO RTT", s.rto.String(), rtt.String())
}

// resendSegment resends the first unacknowledged segment.
// tcp的拥塞控制：快速重传
// 快速重传就是基于以下机制：
// 如果假设重复阈值为3，当发送方收到4次相同确认号的分段确认（第1次收到确认期望序列号，加3次重复的期望序列号确认）时，
// 则可以认为继续发送更高序列号的分段将会被接受方丢弃，而且会无法有序送达。
// 发送方应该忽略超时计时器的等待重发，立即重发重复分段确认中确认号对应序列号的分段。
func (s *sender) resendSegment() {
  // Don't use any segments we already sent to measure RTT as they may
  // have been affected by packets being lost.
  s.rttMeasureSeqNum = s.sndNxt

  // Resend the segment.
  if seg := s.writeList.Front(); seg != nil {
		logger.NOTICE("重复发送...")
    s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)
  }
}

// sendSegment sends a new segment containing the given payload, flags and
// sequence number.
// 根据给定的参数，负载数据、flags标记和序列号来发送数据
func (s *sender) sendSegment(data buffer.VectorisedView, flags byte, seq seqnum.Value) *tcpip.Error {
	s.lastSendTime = time.Now()
	if seq == s.rttMeasureSeqNum {
		s.rttMeasureTime = s.lastSendTime
	}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.maxSentAck = rcvNxt

	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}

// 收到段时调用 handleRcvdSegment 它负责更新与发送相关的状态
func (s *sender) handleRcvdSegment(seg *segment) {
	// 如果rtt测量seq小于ack num，更新rto
	if !s.ep.sendTSOk && s.rttMeasureSeqNum.LessThan(seg.ackNumber) {
		s.updateRTO(time.Now().Sub(s.rttMeasureTime))
		s.rttMeasureSeqNum = s.sndNxt
	}

	// tcp的拥塞控制：检查是否有重复的ack，是否进入快速重传和快速恢复状态
	rtx := s.checkDuplicateAck(seg)

	// 存放当前窗口大小。
	s.sndWnd = seg.window
	// 获取确认号
	ack := seg.ackNumber
	// 如果ack在最小未确认的seq和segNext之间
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {
		// 收到了东西 就暂停计时
		s.resendTimer.disable()

		if s.ep.sendTSOk && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond
			// granularity.
			elapsed := time.Duration(s.ep.timestamp()-seg.parsedOptions.TSEcr) * time.Millisecond
			s.updateRTO(elapsed)
		}
		// 获取这次确认的字节数，即 ack - snaUna
		acked := s.sndUna.Size(ack)
		// 更新下一个未确认的序列号
		s.sndUna = ack

		ackLeft := acked
		originalOutstanding := s.outstanding
		// 从发送链表中删除已经确认的数据，发送窗口的滑动。
		for ackLeft > 0 { // 有成功确认的数据 丢弃它们 有剩余数据的话继续发送(根据拥塞策略控制)
			seg := s.writeList.Front()
			datalen := seg.logicalLen()

			if datalen > ackLeft {
				seg.data.TrimFront(int(ackLeft))
				break
			}

			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}
			// 从发送链表中删除已确认的tcp段。
			s.writeList.Remove(seg)
			// 因为有一个tcp段确认了，所以 outstanding 减1
			s.outstanding--
			seg.decRef()
			ackLeft -= datalen
		}
		// 当收到ack确认时，需要更新发送缓冲占用
		s.ep.updateSndBufferUsage(int(acked))

		// tcp拥塞控制：如果没有进入快速恢复状态，那么根据确认的数据包的数量更新拥塞窗口。
    if !s.fr.active {
      // 调用相应拥塞控制算法的 Update
      s.cc.Update(originalOutstanding - s.outstanding)
    }


		// 如果发生超时重传时，s.outstanding可能会降到零以下，
		// 重置为零但后来得到一个覆盖先前发送数据的确认。
		if s.outstanding < 0 {
			s.outstanding = 0
		}
	}

	// tcp拥塞控制 快速重传
	if rtx {
		logger.NOTICE("重复收到3个ack报文 启动快速重传...")
		s.resendSegment()
	}
	//log.Fatal(s.sndCwnd, s.sndSsthresh)

	if s.ep.id.LocalPort != 9999 {
		log.Println(s)
	}

	// 现在某些待处理数据已被确认，或者窗口打开，或者由于快速恢复期间出现重复的ack而导致拥塞窗口膨胀，
	// 因此发送更多数据。如果需要，这也将重新启用重传计时器。
	s.sendData()
}

// tcp的可靠性：重传定时器触发的时候调用这个函数，也就是超时重传
// tcp的拥塞控制：发生重传即认为发送丢包，拥塞控制需要对丢包进行相应的处理。
func (s *sender) retransmitTimerExpired() bool {
	// 检查计时器是否真的到期
	if !s.resendTimer.checkExpiration() {
		return true
	}

	// 如果rto已经超过了1分钟，直接放弃发送，返回错误
	if s.rto >= 60*time.Second {
		return false
	}
	// 每次超时，rto都变成原来的2倍
	s.rto *= 2

	// TODO 拥塞控制
	// FIXME 添加拥塞控制逻辑

	// tcp可靠性：将下一个段标记为第一个未确认的段，然后再次开始发送。将未完成的数据包数设置为0，以便我们能够重新传输。
	// 当我们收到我们传输的数据时，我们将继续传输（或重新传输）。
	s.outstanding = 0
	s.writeNext = s.writeList.Front()
	// 重新发送数据包
	logger.NOTICE("超时重发")
	s.sendData()
	return true
}

// 发送数据段，最终调用 sendSegment 来发送
func (s *sender) sendData() {
	limit := s.maxPayloadSize //最开始是65483

	// 如果TCP在超过重新传输超时的时间间隔内没有发送数据，TCP应该在开始传输之前将cwnd设置为不超过RW。
	if !s.fr.active && time.Now().Sub(s.lastSendTime) > s.rto {
		log.Fatal("重置sndCwnd")
		if s.sndCwnd > InitialCwnd {
			s.sndCwnd = InitialCwnd
		}
	}

	var seg *segment
	end := s.sndUna.Add(s.sndWnd)
	var dataSent bool
	// 遍历发送链表，发送数据
	// tcp拥塞控制：s.outstanding < s.sndCwnd 判断正在发送的数据量不能超过拥塞窗口。
	for seg = s.writeNext; seg != nil && s.outstanding < s.sndCwnd; seg = seg.Next() { // 首次发送不会超过两个包
		// 如果seg的flags是0，将flags改为psh|ack
		if seg.flags == 0 {
			seg.sequenceNumber = s.sndNxt
			seg.flags = flagAck | flagPsh
		}

		var segEnd seqnum.Value
		if seg.data.Size() == 0 { // 数据段没有负载，表示要结束连接
			if s.writeList.Back() != seg {
				panic("FIN segments must be the final segment in the write list.")
			}
			// 发送 fin 报文
			seg.flags = flagAck | flagFin
			// fin 报文需要确认，且消耗一个字节序列号
			segEnd = seg.sequenceNumber.Add(1)
		} else {
			// We're sending a non-FIN segment.
			if seg.flags&flagFin != 0 {
				panic("Netstack queues FIN segments without data.")
			}
			if !seg.sequenceNumber.LessThan(end) {
				log.Println("暂停数据发送 等待确认标号", seg.sequenceNumber, " 已收到 。。。。")
				break
			}

			// tcp流量控制：计算最多一次发送多大数据，
			available := int(seg.sequenceNumber.Size(end))
			if available > limit {
				available = limit
			}

			// 如果seg的payload字节数大于available
			// 将seg进行分段，并且插入到该seg的后面
			if seg.data.Size() > available {
				nSeg := seg.clone()
				nSeg.data.TrimFront(available) // NOTE 删掉用过的
				nSeg.sequenceNumber.UpdateForward(seqnum.Size(available))
				s.writeList.InsertAfter(seg, nSeg)
				seg.data.CapLength(available)
			}

			s.outstanding++
			segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
			log.Println("发送窗口是", s.sndWnd,
				"最多发送数据", available,
				"缓存数据头", seg.sequenceNumber,
				"缓存数据尾", segEnd,
				"发送端缓存包数量", s.outstanding)
		}

		if !dataSent { // 没有成功发送任何数据
			dataSent = true
			// TODO
		}

		s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)
		// 发送一个数据段后，更新sndNxt
		if s.sndNxt.LessThan(segEnd) {
			log.Println("更新sndNxt", s.sndNxt, " 为 ", segEnd, "下一次发送的数据头为", segEnd)
			s.sndNxt = segEnd
		}
	}
	// Remember the next segment we'll write.
	s.writeNext = seg

	// 如果重传定时器没有启动 且 sndUna != sndNxt 启动定时器
	if !s.resendTimer.enabled() && s.sndUna != s.sndNxt {
		// NOTE 开启计时器 如果在RTO后没有回信(snd.handleRecvdSegment 中有数据可以处理) 那么将会重发
		// 在 s.resendTimer.init() 中 将会调用 Assert() 唤醒重发函数 retransmitTimerExpired()
		s.resendTimer.enable(s.rto)
	}

	// NOTE 如果我们的发送窗口被缩到0 我们需要定时去问一下对端消费完了没
	if s.sndUna == s.sndNxt {
		s.ep.resetKeepaliveTimer(false)
	}
}

// 进入快速恢复和相应的处理 快速重传和快速恢复算法一般同时使用。
// 快速恢复算法是认为，你还有 3 个Duplicated Acks回来，说明网络也不那么糟糕，所以没有必要像 RTO 超时那么强烈
func (s *sender) enterFastRecovery() {
	s.fr.active = true
	// 注意，正如前面所说，进入快速重传之前，sshthresh 已被更新ssthresh = max (cwnd/2, 2)然后，真正的Fast Recovery算法如下：
	// 1. cwnd = sshthresh + 3（3 的意思是确认有 3 个数据包被收到了）
	// 2. 重传重复 ACKs 指定的数据包
	// 3. 如果再收到重复 Acks，那么cwnd = cwnd + 1；如果收到了新的 Ack，那么，cwnd = sshthresh，然后就进入了拥塞避免的算法了。
	s.sndCwnd = s.sndSsthresh + 3
  s.fr.first = s.sndUna
  s.fr.last = s.sndNxt - 1
	logger.NOTICE("快速恢复的范围: ", atoi(s.fr.first), atoi(s.fr.last), atoi(s.fr.last-s.fr.first)) // 一般是4个报文的长度
  s.fr.maxCwnd = s.sndCwnd + s.outstanding
}

// tcp拥塞控制：退出快速恢复状态和相应的处理
func (s *sender) leaveFastRecovery() {
  s.fr.active = false
  s.fr.first = 0
  s.fr.last = s.sndNxt - 1
  s.fr.maxCwnd = 0
  s.dupAckCount = 0

  // Deflate cwnd. It had been artificially inflated when new dups arrived.
  s.sndCwnd = s.sndSsthresh
  s.cc.PostRecovery()
}


// tcp拥塞控制：收到确认时调用 checkDuplicateAck。它管理与重复确认相关的状态，
// 并根据RFC 6582（NewReno）中的规则确定是否需要重新传输
func (s *sender) checkDuplicateAck(seg *segment) (rtx bool) {
	ack := seg.ackNumber
	//logger.NOTICE("注意测试", atoi(s.sndCwnd))
	// 已经启动了快速恢复
	if s.fr.active {
	}

	// 我们还没有进入快速恢复状态，只有当段不携带任何数据并且不更新发送窗口时，才认为该段是重复的。
	if ack != s.sndUna /*最新的没有被确认的seq*/ ||
		seg.logicalLen() != 0 /*没有任何数据的ack包*/ ||
		s.sndWnd != seg.window /*不要求更新窗口*/ ||
		ack == s.sndNxt {
		s.dupAckCount = 0
		return false
	}

	// 到这表示收到一个重复的ack
	s.dupAckCount++

	// 收到三次的重复ack才会进入快速恢复。
	if s.dupAckCount < nDupAckThreshold {
		return false
	}

	// 调用拥塞控制的 HandleNDupAcks 处理三次重复ack
	// 这里将会缩小拥塞阈值
	s.cc.HandleNDupAcks()
	// 进入快速恢复状态
	s.enterFastRecovery()
	s.dupAckCount = 0
	return true
}

var fmtSender string = `%s
    	         +----->  % 10s  <------+
                 |    Scale  % 4s            |
-----------------+-------------+-------------+------------------
|      已确认    |UAC% 10s|NXT% 10s|   不可发送
-----------------+-------------+-------------+------------------
                 ^             ^
                 |             |
             % 10s    % 10s`

func (s sender) String() string {
	return fmt.Sprintf(fmtSender,
		atoi(s.ep.id.LocalPort),
		atoi(s.sndWnd), atoi(s.sndWndScale),
		atoi(s.sndNxt-s.sndUna), atoi(s.ep.sndBufSize-s.ep.sndBufUsed),
		atoi(s.sndUna), atoi(s.sndNxt))
}

func atoi[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | seqnum.Size | seqnum.Value](i T) string {
	return fmt.Sprintf("%d", i)
}
