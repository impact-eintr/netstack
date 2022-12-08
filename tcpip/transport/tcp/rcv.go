package tcp

import (
	"log"
	"netstack/tcpip/seqnum"
)

type receiver struct{}

// 新建并初始化接收器
func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	r := &receiver{}
	return r
}

// handleRcvdSegment handles TCP segments directed at the connection managed by
// r as they arrive. It is called by the protocol main loop.
// 从 handleSegments 接收到tcp段，然后进行处理消费，所谓的消费就是将负载内容插入到接收队列中
func (r *receiver) handleRcvdSegment(s *segment) {
	log.Println(s.data)

}
