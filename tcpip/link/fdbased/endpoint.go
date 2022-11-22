package fdbased

import (
	"netstack/tcpip"
	"netstack/tcpip/stack"
	"syscall"
)

// 从NIC读取数据的多级缓存配置
var BufConfig = []int{1<<7, 1<<8, 1<<8, 1<<9, 1<<10, 1<<11, 1<<12, 1<<13, 1<<14, 1<<15}

// 负责底层网卡的io读写以及数据分发
type endpoint struct {
	// 发送和接收数据的文件爱你描述符
	fd int
	// 单个帧的最大长度
	mtu uint32
	// 以太网头部长度
	hdrSize int
	// 网卡地址
	addr tcpip.LinkAddress
	// 网卡的能力
	caps stack.LinkEndpointCapabilities

	closed func(*tcpip.Error)

	iovers []syscall.Iovec
	views []buffer.View
	dispatcher stack.NetworkDispatcher

	// handleLocal指示发往自身的数据包是由内部netstack处理（true）还是转发到FD端点（false）
	handleLocal bool
}

type Options struct {
	FD int
	MTU uint32
	ClosedFunc func(*tcpip.Error)
	Address tcpip.LinkAddress
	ResolutionRequired bool
	SaveRestore        bool
	ChecksumOffload    bool
	DisconnectOk       bool
	HandleLocal        bool
	TestLossPacket     func(data []byte) bool
}
