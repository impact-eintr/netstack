package tcp

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/seqnum"
	"time"
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

	// sndNxt 是要发送的下一个段的序列号。
	sndNxt seqnum.Value

	// maxSentAck is the maxium acknowledgement actually sent.
	maxSentAck seqnum.Value

	// cc is the congestion control algorithm in use for this sender.
	// cc 是实现拥塞控制算法的接口
	cc congestionControl
}

// 新建并初始化发送器 irs是cookies
func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	s := &sender{
		ep:         ep,
		sndNxt:     iss + 1,
		maxSentAck: irs + 1,
	}
	return s
}

func (s *sender) sendAck() {
	log.Println("发送字节序", s.sndNxt)
	s.sendSegment(buffer.VectorisedView{}, flagAck, s.sndNxt) // seq = cookies+1 ack ack|fin.seq+1
	s.sendSegment(buffer.VectorisedView{}, flagFin, 0)
}

// sendSegment sends a new segment containing the given payload, flags and
// sequence number.
// 根据给定的参数，负载数据、flags标记和序列号来发送数据
func (s *sender) sendSegment(data buffer.VectorisedView, flags byte, seq seqnum.Value) *tcpip.Error {
	s.lastSendTime = time.Now()
	//if seq == s.rttMeasureSeqNum {
	//	s.rttMeasureTime = s.lastSendTime
	//}

	rcvNxt, rcvWnd := s.ep.rcv.getSendParams()

	// Remember the max sent ack.
	s.maxSentAck = rcvNxt

	return s.ep.sendRaw(data, flags, seq, rcvNxt, rcvWnd)
}

// 收到段时调用 handleRcvdSegment 它负责更新与发送相关的状态
func (s *sender) handleRcvdSegment(seg *segment) {
	// 现在某些待处理数据已被确认，或者窗口打开，或者由于快速恢复期间出现重复的ack而导致拥塞窗口膨胀，
	// 因此发送更多数据。如果需要，这也将重新启用重传计时器。
	s.sendData()
}

// 发送数据段，最终调用 sendSegment 来发送
func (s *sender) sendData() {

}
