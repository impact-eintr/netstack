package tcp

import (
	"log"
	"netstack/tcpip/seqnum"
)

type receiver struct {
	ep     *endpoint
	rcvNxt seqnum.Value // 准备接收的下一个报文序列号
	closed bool
}

// 新建并初始化接收器
func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	r := &receiver{
		ep:     ep,
		rcvNxt: irs + 1,
	}
	return r
}

// tcp流量控制：判断 segSeq 在窗口內
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	// TODO 流量控制
	return true
}

func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		// 我们期望接收到的序列号范围应该是 seqStart <= rcvNxt < seqEnd，
		// 如果不在这个范围内说明我们少了数据段，返回false，表示不能立马消费
		if !r.rcvNxt.InWindows(segSeq, segLen) {
			return false
		}
		// 尝试去除已经确认过的数据
		if segSeq.LessThan(r.rcvNxt) {
			log.Println("收到重复数据")
			diff := segSeq.Size(r.rcvNxt)
			segLen -= diff
			segSeq.UpdateForward(diff)
			s.sequenceNumber.UpdateForward(diff)
			s.data.TrimFront(int(diff))
		}
		// 将tcp段插入接收链表，并通知应用层用数据来了
		r.ep.readyToRead(s)
	} else if segSeq != r.rcvNxt { // 空数据 还是非顺序到达 丢弃
		return false
	}

	// 如果收到 fin 报文
	if s.flagIsSet(flagFin) {
		// TODO 处理fin报文
	}

	return true
}

// handleRcvdSegment handles TCP segments directed at the connection managed by
// r as they arrive. It is called by the protocol main loop.
// 从 handleSegments 接收到tcp段，然后进行处理消费，所谓的消费就是将负载内容插入到接收队列中
func (r *receiver) handleRcvdSegment(s *segment) {
	if r.closed {
		return
	}
	segLen := seqnum.Size(s.data.Size())
	segSeq := s.sequenceNumber

	// TODO tcp流量控制
	// tcp流量控制：判断该数据段的序列号是否在接收窗口内，如果不在，立即返回ack给对端。
	if !r.acceptable(segSeq, segLen) {
		r.ep.snd.sendAck()
		return
	}

	log.Println(s.data, segLen, segSeq)

	// Defer segment processing if it can't be consumed now.
	// tcp可靠性：r.consumeSegment 返回值是个bool类型，如果是true，表示已经消费该数据段，
	// 如果不是，那么进行下面的处理，插入到 pendingRcvdSegments，且进行堆排序
	if !r.consumeSegment(s, segSeq, segLen) {
		return
	}

}
