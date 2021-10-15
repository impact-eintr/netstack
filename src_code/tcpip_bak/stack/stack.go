package stack

import (
	"sync"
	"time"

	"github.com/impact-eintr/netstack/sleep"
	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
	"github.com/impact-eintr/netstack/tcpip/ports"
	"github.com/impact-eintr/netstack/tcpip/seqnum"
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.VectorisedView) bool
}

// Stack 是一个网络堆栈，包含所有支持的协议、NIC 和路由表
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol
	linkAddrResolvers  map[tcpip.NetworkProtocolNumber]LinkAddressResolver

	demux *transportDemuxer

	stats tcpip.Stats

	linkAddrCache *linkAddrCache

	mu         sync.RWMutex
	nics       map[tcpip.NICID]*NIC
	forwarding bool

	// route 是用户通过 SetRouteTable() 传入的路由表，Find Route() 使用它来构建特定目的地的路由
	routeTable []tcpip.Route

	*ports.PortManager
	// 如果不是 nil，则任何新端点每次收到 TCP 段时都会调用此探测函数
	tcpProbeFunc TCPProbeFunc
	// 用于生成用户可见的时间
	clock tcpip.Clock
}

type Options struct {
	Clock tcpip.Clock
	Stats tcpip.Stats
}

// TCPProbeFunc 是要传递给 stack.AddTCPProbe 的 TCP 探测函数的预期函数类型
type TCPProbeFunc func(s TCPEndpointState)

// TCPEndpointState 是 TCP 端点内部状态的副本
type TCPEndpointState struct {
	ID         TCPEndpointID // ID 是端点的 TransportEndpointID 的副本
	SegTime    time.Time     // SegTime 表示收到该段的绝对时间
	RcvBufSize int           // RcvBufSize 是端点的接收套接字缓冲区的大小
	RcvBufUsed bool          // RcvBufUsed 是端点的接收套接字缓冲区中实际保存的字节数
	RcvClosed  bool          // RcvClosed 如果为真，表示端点已经关闭读取
	SendTSOk   bool          // SendOk 用于指示何时协商了 TS 选项。当 sendOk 为真时，每个非 RST 段都应根据 RFC 7323#section-1.1 携带 TS

	// 应该在时间戳的TSEcr 字段中为端点发送的未来段发送的时间戳。当此端点接收到新段时，如果需要，将更新此字段
	RecentTS uint32
	// TSOffset 是添加到时间戳选项中 TSVal 字段值的随机偏移量
	TSOffset uint32

	// 如果对等方在 SYN/SYN-ACK 中发送 TCPSACKPermitted 选项，则 SACKPermitted 设置为 true
	SACKPermitted bool
	SACK          TCPSACKInfo // SACK 保存该端点的 TCP SACK 相关信息
	SndBufSize    int         // SndBufSize 是套接字发送缓冲区的大小
	SndBufUsed    bool        // SndBufUsed 是端点的发送套接字缓冲区中实际发送的字节数
	SndClosed     bool        // SndClosed 表示端点已关闭发送

	sndBufInQueue seqnum.Size // SndBufInQueue 是发送队列中的字节数

	// PacketTooBigCount 用于通知主协程收到“数据包太大”控制数据包的次数
	PacketTooBigCount int

	SndMTU   int // SndMTU 是在收到的控制数据包中看到的最小 MTU
	Receiver TCPReceiverState
	Sender   TCPSenderState
}

type TCPReceiverState struct {
}

type TCPSenderState struct {
}

// 根据nic id和linkEP id来创建和注册一个网卡对象
func (s *Stack) CreateNIC(id tcpip.NICID, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, "", linkEP, true)
}

func (s *Stack) CreateNamedNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, true)
}

func (s *Stack) CreateDisableNamedNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID) *tcpip.Error {
	return s.createNIC(id, name, linkEP, false)
}

// 新建一个网卡对象，并且激活它，激活的意思就是准备好从网卡中读取和写入数据
func (s *Stack) createNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID, enabled bool) *tcpip.Error {
	ep := FindLinkEndpoint(linkEP)
	if ep == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nics[id]; ok {

	}

	n := newNIC(s, id, name, ep)

	s.nics[id] = n
	if enabled {
		n.attachLinkEndpoint()
	}
	return nil

}

// CheckLocalAddress 确定给定的本地地址是否存在
func (s *Stack) CahceLocalAddress(nicid tcpip.NICID, protocol tcpip.NetworkProtocolNumber,
	addr tcpip.Address) tcpip.NICID

// AddLinkAddress 向缓存添加链接地址
func (s *Stack) AddLinkAddress(nicid tcpip.NICID, addr tcpip.Address, linkAddr tcpip.LinkAddress)

// GetLinkAddress 查找缓存以将地址转换为链接地址（例如 IP -> MAC）。
// 如果 LinkEndpoint 请求地址解析并且存在使用网络协议注册的 Link Address Resolver，则缓存尝试解析地址并返回 EWouldBlock。
// 如果需要地址解析，则返回 ErrNoLinkAddress 和通知通道以供顶级调用方阻止。 一旦地址解析完成（成功与否），通道就会关闭。
func (s *Stack) GetLinkAddress(nic tcpip.NICID, addr, localAddr tcpip.Address,
	protocol tcpip.NetworkProtocolNumber, ww *sleep.Waker) (tcpip.LinkAddress,
	<-chan struct{}, *tcpip.Error) {

}

// RemoveWaker 移除已在 GetLinkAddress() 中添加的唤醒器。
func (s *Stack) RemoveWaker(nicid tcpip.NICID, addr tcpip.Address, waker *sleep.Waker) {

}

// 当NIC从物理接口接受数据包时，将调用此函数
// 比如protocol是arp协议号 那么会找到arp.HandlePacket来处理数据报
// protocol是ipv4协议号，那么会找到ipv4.HahndlePacket来处理数据报
func (s *Stack) DeliverNetworkPacket(linkEP LinkEndpoint, dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {

}
