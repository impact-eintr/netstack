package tcp

import (
	"log"
	"netstack/tcpip"
)

// The following are used to set up sleepers.
const (
	wakerForNotification = iota
	wakerForNewSegment
	wakerForResend
	wakerForResolution
)

const maxSegmentsPerWake = 100

// protocolMainLoop 是TCP协议的主循环。它在自己的goroutine中运行，负责握手、发送段和处理收到的段
func (e *endpoint) protocolMainLoop(handshake bool) *tcpip.Error {
	for {
		log.Println("三次握手机制在这里实现")
		select {}
	}
}
