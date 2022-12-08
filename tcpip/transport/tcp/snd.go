package tcp

import (
	"log"
	"netstack/tcpip/seqnum"
)

type sender struct {
}

// 新建并初始化发送器
func newSender(ep *endpoint, iss, irs seqnum.Value, sndWnd seqnum.Size, mss uint16, sndWndScale int) *sender {
	s := &sender{}
	return s
}

func (s *sender) sendAck() {
	log.Fatal("TODO 需要发送一个ack")
}
