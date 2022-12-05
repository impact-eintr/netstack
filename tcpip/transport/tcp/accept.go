package tcp

import (
	"netstack/tcpip"
	"netstack/tcpip/seqnum"
)

// protocolListenLoop 是侦听TCP端点的主循环。它在自己的goroutine中运行，负责处理连接请求
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) *tcpip.Error {
	select {}
}
