package fdbased

import (
	"syscall"

	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
	"github.com/impact-eintr/netstack/tcpip/stack"
)

// 负责底层网卡的io读写以及数据分发
type endpoint struct {
	// 发送和接收数据的文件描述符
	fd int

	// 单个帧的最大长度
	mtu uint32

	// 以太网头部长度
	hdrSize int

	// 网卡地址
	addr tcpip.LinkAddress

	// 网卡的能力
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	iovecs     []syscall.Iovec
	views      []buffer.View
	dispatcher stack.NetworkDispatcher

	// handleLocal indicates whether packets destined to itself should be
	// handled by the netstack internally (true) or be forwarded to the FD
	// endpoint (false).
	// handleLocal指示发往自身的数据包是由内部netstack处理（true）还是转发到FD端点（false）。
	// Resend packets back to netstack if destined to itself
	// Add option to redirect packet back to netstack if it's destined to itself.
	// This fixes the problem where connecting to the local NIC address would
	// not work, e.g.:
	// echo bar | nc -l -p 8080 &
	// echo foo | nc 192.168.0.2 8080
	handleLocal bool
}
