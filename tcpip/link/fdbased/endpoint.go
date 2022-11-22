package fdbased

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/link/rawfile"
	"netstack/tcpip/stack"
	"syscall"
)

// 从NIC读取数据的多级缓存配置
var BufConfig = []int{1<<7, 1<<8, 1<<8, 1<<9, 1<<10, 1<<11, 1<<12, 1<<13, 1<<14, 1<<15}

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

// 根据选项参数创建一个链路层的endpoint，并返回该endpoint的id
func New(opts *Options) tcpip.LinkEndpointID {
	syscall.SetNonblock(opts.FD, true)
	caps := stack.LinkEndpointCapabilities(0) // 初始化
	if opts.ResolutionRequired {
		caps |= stack.CapabilityResolutionRequired
	}
	if opts.ChecksumOffload {
		caps |= stack.CapabilityChecksumOffload
	}
	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}
	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOK
	}

	e := &endpoint{
		fd: opts.FD,
		mtu: opts.MTU,
		caps: caps,
		closed: opts.ClosedFunc,
		addr: opts.Address,
		hdrSize: header.EthernetMinimumSize,
		views: make([]buffer.View, len(BufConfig)),
		iovers: make([]syscall.Iovec, len(BufConfig)),
		handleLocal: opts.HandleLocal,
	}

	// 全局注册链路层设备
	return stack.RegisterLinkEndpoint(e)
}

func (e *endpoint)	MTU() uint32 {
	return e.mtu
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// 返回当前以太网头部信息长度
func (e *endpoint)	MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// 返回当前MAC地址
func (e *endpoint)	LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// 将上层的报文经过链路层封装，写入网卡中，如果写入失败则丢弃该报文
func (e *endpoint)	WritePacket(r *stack.Route, hdr buffer.Prependable,
	payload buffer.VectorisedView,	protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	// 如果目标地址是设备自己 那么将报文重新返回给协议栈
	if e.handleLocal && r.LocalAddress != "" && r.LocalAddress == r.RemoteAddress {
		views := make([]buffer.View, 1, 1+len(payload.Views()))
		views[0] = hdr.View()
		views = append(views, payload.Views()...)
		vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views) // 添加报文头
		e.dispatcher.DeliverNetworkPacket(e, r.RemoteLinkAddress, r.LocalLinkAddress,
			protocol, vv) // 分发数据报
		return nil
	}
	// 封装增加以太网头部
	eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize)) // 分配14B的内存
	ethHdr := &header.EthernetFields{ // 配置以太帧信息
		DstAddr: r.RemoteLinkAddress,
		Type: protocol,
	}
	// 如果路由信息中有配置源MAC地址，那么使用该地址
	// 如果没有，则使用本网卡的地址
	if r.LocalLinkAddress != "" {
		ethHdr.SrcAddr = r.LocalLinkAddress // 源网卡地址 说明这是一个转发报文
	} else {
		ethHdr.SrcAddr = e.addr // 说明这是一个原始报文
	}
	eth.Encode(ethHdr) // 将以太帧信息作为报文头编入
	// 写入网卡中
	if payload.Size() == 0 {
		return rawfile
	}
}

// Attach 启动从文件描述符中读取数据包的goroutine,并通过提供的分发函数来分发数据报
func (e *endpoint)	Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// 链接端点不可靠。保存传输端点后，它们将停止发送传出数据包，并拒绝所有传入数据包。
	go e.dispatchLoop()
}

func (e *endpoint)	IsAttached() bool {
	return e.dispatcher != nil
}
