package tcp

import (
	"log"
	"netstack/logger"
	"netstack/tcpip/seqnum"
)

type receiver struct {
	ep     *endpoint
	rcvNxt seqnum.Value // 准备接收的下一个报文序列号

	// rcvAcc 超出了最后一个可接受的序列号。也就是说，接收方向其同行宣布它愿意接受的“最大”序列值。
	// 如果接收窗口减少，这可能与rcvNxt + rcvWnd不同;在这种情况下，我们必须减少窗口，因为我们收到更多数据而不是缩小它。
	rcvAcc      seqnum.Value
	rcvWndScale uint8

	closed bool

	pendingRcvdSegments segmentHeap
	pendingBufUsed      seqnum.Size
	pendingBufSize      seqnum.Size
}

// 新建并初始化接收器
func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	r := &receiver{
		ep:             ep,
		rcvNxt:         irs + 1, // 成功建立连接后期望读取的第一个字节序号
		rcvAcc:         irs.Add(rcvWnd + 1),
		rcvWndScale:    rcvWndScale,
		pendingBufSize: rcvWnd,
	}
	return r
}

// tcp流量控制：判断 segSeq 在窗口內
func (r *receiver) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	rcvWnd := r.rcvNxt.Size(r.rcvAcc)
	if rcvWnd == 0 {
		return segLen == 0 && segSeq == r.rcvNxt // 是否卡在边上
	}

	return segSeq.InWindow(r.rcvNxt, rcvWnd) || // 在窗口内部
		seqnum.Overlap(r.rcvNxt, rcvWnd, segSeq, segLen) // 范围有重叠
}

// getSendParams returns the parameters needed by the sender when building
// segments to send.
// getSendParams 在构建要发送的段时，返回发送方所需的参数。
// 并且更新接收窗口的指标 rcvAcc
func (r *receiver) getSendParams() (rcvNxt seqnum.Value, rcvWnd seqnum.Size) {
	// Calculate the window size based on the current buffer size.
	n := r.ep.receiveBufferAvailable()
	acc := r.rcvNxt.Add(seqnum.Size(n))
	if r.rcvAcc.LessThan(acc) {
		r.rcvAcc = acc
	}

	return r.rcvNxt, r.rcvNxt.Size(r.rcvAcc) >> r.rcvWndScale
}

func (r *receiver) consumeSegment(s *segment, segSeq seqnum.Value, segLen seqnum.Size) bool {
	if segLen > 0 {
		// 我们期望接收到的序列号范围应该是 seqStart <= rcvNxt < seqEnd，
		// 如果不在这个范围内说明我们少了数据段，返回false，表示不能立马消费
		if !r.rcvNxt.InWindow(segSeq, segLen) {
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

	// 因为前面已经收到正确按序到达的数据，那么我们应该更新一下我们期望下次收到的序列号了
	r.rcvNxt = segSeq.Add(segLen)
	logger.GetInstance().Info(logger.TCP, func() {
	})

	// 如果收到 fin 报文
	if s.flagIsSet(flagFin) {
		// 控制报文消耗一个字节的序列号，因此这边期望下次收到的序列号加1
		r.rcvNxt++

		// 收到 fin，立即回复 ack
		r.ep.snd.sendAck()

		// 标记接收器关闭
		// 触发上层应用可以读取
		r.closed = true
		r.ep.readyToRead(nil)
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

	//log.Println(s.data, segLen, segSeq)

	// Defer segment processing if it can't be consumed now.
	// tcp可靠性：r.consumeSegment 返回值是个bool类型，如果是true，表示已经消费该数据段，
	// 如果不是，那么进行下面的处理，插入到 pendingRcvdSegments，且进行堆排序
	if !r.consumeSegment(s, segSeq, segLen) {
		return
	}

}
