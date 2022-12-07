package tcp

import "netstack/tcpip/seqnum"

type receiver struct{}

// 新建并初始化接收器
func newReceiver(ep *endpoint, irs seqnum.Value, rcvWnd seqnum.Size, rcvWndScale uint8) *receiver {
	r := &receiver{}
	return r
}
