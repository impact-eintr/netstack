package fdbased

import (
	"log"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/link/rawfile"
	"netstack/tcpip/stack"
	"syscall"
)

// 从NIC读取数据的多级缓存配置
var BufConfig = []int{1 << 7, 1 << 8, 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15}

// 负责底层网卡的io读写以及数据分发
// NOTE 也就是网卡驱动
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

	iovecs     []syscall.Iovec
	views      []buffer.View
	dispatcher stack.NetworkDispatcher

	// handleLocal指示发往自身的数据包是由内部netstack处理（true）还是转发到FD端点（false）
	handleLocal bool
}

type Options struct {
	FD                 int
	MTU                uint32
	ClosedFunc         func(*tcpip.Error)
	Address            tcpip.LinkAddress
	ResolutionRequired bool
	SaveRestore        bool
	ChecksumOffload    bool
	DisconnectOk       bool
	HandleLocal        bool
	TestLossPacket     func(data []byte) bool
}

// New 根据选项参数创建一个链路层的endpoint，并返回该endpoint的id
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
		fd:          opts.FD,
		mtu:         opts.MTU,
		caps:        caps,
		closed:      opts.ClosedFunc,
		addr:        opts.Address,
		hdrSize:     header.EthernetMinimumSize,
		views:       make([]buffer.View, len(BufConfig)),
		iovecs:      make([]syscall.Iovec, len(BufConfig)),
		handleLocal: opts.HandleLocal,
	}
	// 全局注册链路层设备
	return stack.RegisterLinkEndpoint(e)
}

func (e *endpoint) MTU() uint32 {
	return e.mtu
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// 返回当前以太网头部信息长度
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// 返回当前MAC地址
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// 将上层的报文经过链路层封装，写入网卡中，如果写入失败则丢弃该报文
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable,
	payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
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
	log.Println(eth,hdr,  hdr.Prepend(header.EthernetMinimumSize))
	ethHdr := &header.EthernetFields{                               // 配置以太帧信息
		DstAddr: r.RemoteLinkAddress,
		Type:    protocol,
	}
	// 如果路由信息中有配置源MAC地址，那么使用该地址
	// 如果没有，则使用本网卡的地址
	if r.LocalLinkAddress != "" {
		ethHdr.SrcAddr = r.LocalLinkAddress
	} else {
		ethHdr.SrcAddr = e.addr
	}
	eth.Encode(ethHdr) // 将以太帧信息作为报文头编入
	logger.GetInstance().Info(logger.ETH, func() {
		log.Println(ethHdr.SrcAddr, "链路层写回以太报文 ", r.RemoteLinkAddress, " to ", r.RemoteAddress)
	})
	// 写入网卡中
	if payload.Size() == 0 {
		return rawfile.NonBlockingWrite(e.fd, hdr.View())
	}
	return rawfile.NonBlockingWrite2(e.fd, hdr.View(), payload.ToView())
}

// Attach 启动从文件描述符中读取数据包的goroutine,并通过提供的分发函数来分发数据报
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// 链接端点不可靠。保存传输端点后，它们将停止发送传出数据包，并拒绝所有传入数据包。
	go e.dispatchLoop()
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// 截取需要的内容
func (e *endpoint) capViews(n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			e.views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

// 按照bufConfig的长度分配内存大小
// 注意e.views 和 e.iovecs共用相同的内存块
func (e *endpoint) allocateViews(bufConfig []int) {
	for i, v := range e.views {
		if v != nil {
			break
		}
		b := buffer.NewView(bufConfig[i]) // 分配内存
		e.views[i] = b
		e.iovecs[i] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}
}

func (e *endpoint) dispatch() (bool, *tcpip.Error) {
	// 读取数据缓存的分配
	e.allocateViews(BufConfig)

	// 从网卡读取数据
	n, err := rawfile.BlockingReadv(e.fd, e.iovecs) // 读到ioves中相当于读到views中
	if err != nil {
		return false, err
	}
	if n <= e.hdrSize {
		return false, nil // 读到的数据比头部还小 直接丢弃
	}

	var (
		p                             tcpip.NetworkProtocolNumber
		remoteLinkAddr, localLinkAddr tcpip.LinkAddress // 目标MAC 源MAC
	)
	// 获取以太网头部信息
	eth := header.Ethernet(e.views[0])
	p = eth.Type()
	remoteLinkAddr = eth.SourceAddress()
	localLinkAddr = eth.DestinationAddress()

	used := e.capViews(n, BufConfig)                  // 从缓存中截有效的内容
	vv := buffer.NewVectorisedView(n, e.views[:used]) // 用这些有效的内容构建vv
	vv.TrimFront(e.hdrSize)                           // 将数据内容删除以太网头部信息 将网络层作为数据头

	switch p {
	case header.ARPProtocolNumber, header.IPv4ProtocolNumber:
		logger.GetInstance().Info(logger.ETH, func() {
			log.Println("链路层收到报文,来自: ", remoteLinkAddr, localLinkAddr)
		})
		e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, localLinkAddr, p, vv)
	case header.IPv6ProtocolNumber:
		// TODO ipv6暂时不感兴趣
		e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, localLinkAddr, p, vv)
	default:
		log.Println("未知类型的非法报文")
	}

	// 将分发后的数据无效化(设置nil可以让gc回收这些内存)
	for i := 0; i < used; i++ {
		e.views[i] = nil
	}

	return true, nil
}

// 循环地从fd中读取数据 然后将数据报分发给协议栈
func (e *endpoint) dispatchLoop() *tcpip.Error {
	for {
		cont, err := e.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err) // 阻塞中
			}
			return err
		}
	}
}
