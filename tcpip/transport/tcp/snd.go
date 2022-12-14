package tcp

import (
	"log"
	"netstack/sleep"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"sync"
	"time"
	"unsafe"
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
	// TODO 需要添加
}

// 新建并初始化发送器 irs是cookies
func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	s := &sender{
		ep:             ep,
		sndCwnd:        InitialCwnd,
		sndWnd:         sndWnd,
		sndUna:         iss + 1,
		sndNxt:         iss + 1, // 缓存长度为0
		sndNxtList:     iss + 1,
		rto:            1 * time.Second,
		lastSendTime:   time.Now(),
		maxPayloadSize: int(mss),
		maxSentAck:     irs + 1,
	}
	// A negative sndWndScale means that no scaling is in use, otherwise we
	// store the scaling value.
	if sndWndScale > 0 {
		s.sndWndScale = uint8(sndWndScale)
	}
	s.updateMaxPayloadSize(int(ep.route.MTU()), 0)
	s.resendTimer.init(&s.resendWaker)
	return s
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

	log.Println(s.ep.id.LocalPort, "要求扩展窗口", s.sndWnd)
	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}

// 收到段时调用 handleRcvdSegment 它负责更新与发送相关的状态
func (s *sender) handleRcvdSegment(seg *segment) {
	// 现在某些待处理数据已被确认，或者窗口打开，或者由于快速恢复期间出现重复的ack而导致拥塞窗口膨胀，
	// 因此发送更多数据。如果需要，这也将重新启用重传计时器。
	// 存放当前窗口大小。
	s.sndWnd = seg.window
	log.Println(s.ep.id.LocalPort, "移动窗口", s.sndWnd)
	// 获取确认号
	ack := seg.ackNumber
	// 如果ack在最小未确认的seq和segNext之间
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {
		log.Printf("[...XXXXXX]-[%d|\t%d\t|%d]==>", s.sndNxt, ack-1, s.sndUna)
		if s.ep.sendTSOk && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond
			// granularity.
			//elapsed := time.Duration(s.ep.timestamp()-seg.parsedOptions.TSEcr) * time.Millisecond
			//s.updateRTO(elapsed)
		}
		// 获取这次确认的字节数，即 ack - snaUna
		acked := s.sndUna.Size(ack)
		// 更新下一个未确认的序列号
		s.sndUna = ack

		ackLeft := acked
		//originalOutstanding := s.outstanding
		// 从发送链表中删除已经确认的数据，发送窗口的滑动。
		//log.Printf("[...XXXXXX]-[%d|\t\t|%d]==>", s.sndNxt, s.sndUna)
		for ackLeft > 0 { // 有成功确认的数据 丢弃它们 有剩余数据的话继续发送(根据拥塞策略控制)
			seg := s.writeList.Front()
			datalen := seg.logicalLen()

			if datalen > ackLeft {
				seg.data.TrimFront(int(ackLeft))
				break
			}

			log.Println(s.writeNext == seg)
			if s.writeNext == seg {
				log.Fatal("更新 下一段")
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

		// 如果发生超时重传时，s.outstanding可能会降到零以下，
		// 重置为零但后来得到一个覆盖先前发送数据的确认。
		if s.outstanding < 0 {
			s.outstanding = 0
		}
	}

	// TODO tcp拥塞控制
	if s.writeList.Front() != nil {
		log.Println("确认成功 继续发送")
	}

	s.sendData()
}

// 发送数据段，最终调用 sendSegment 来发送
func (s *sender) sendData() {
	limit := s.maxPayloadSize //最开始是65483

	var seg *segment
	end := s.sndUna.Add(s.sndWnd)
	var dataSent bool
	// 遍历发送链表，发送数据
	// tcp拥塞控制：s.outstanding < s.sndCwnd 判断正在发送的数据量不能超过拥塞窗口。
	for seg = s.writeNext; seg != nil && s.outstanding < s.sndCwnd; seg = seg.Next() {
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
				log.Println("暂停数据发送", seg.sequenceNumber, end)
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
				log.Println("-------------------------------------分段！！！", seg.data.Size(), available, end)
				nSeg := seg.clone()
				nSeg.sequenceNumber.UpdateForward(seqnum.Size(available))
				s.writeList.InsertAfter(seg, nSeg)
				seg.data.CapLength(available)
			}

			s.outstanding++
			segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
			log.Println("发送窗口一开始是", s.sndWnd,
				"最多发送数据", available,
				"缓存数据尾", segEnd,
				"发送端缓存包数量", s.outstanding)
		}

		if !dataSent { // 上面有个break能跳过这一步
			dataSent = true
			// TODO
		}

		s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)
		// 发送一个数据段后，更新sndNxt
		if s.sndNxt.LessThan(segEnd) {
			log.Println("更新sndNxt", s.sndNxt, segEnd)
			s.sndNxt = segEnd
		}
	}
	// Remember the next segment we'll write.
	s.writeNext = seg
	if seg != nil {
		log.Println("-------------------------------------分段！！！", s.writeNext.data.Size())
		log.Println(unsafe.Pointer(seg), seg.data.Size())
	}

	time.Sleep(200 * time.Millisecond)

	// TODO 启动定时器
}
