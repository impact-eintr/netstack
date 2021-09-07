package stack

import (
	"sync"
	"time"

	"github.com/impact-eintr/netstack/tcpip"
	"github.com/impact-eintr/netstack/tcpip/buffer"
	"github.com/impact-eintr/netstack/tcpip/ports"
	"github.com/impact-eintr/netstack/tcpip/seqnum"
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(*Route, TransportEndpointID, buffer.VectorisedView) bool
}

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

	routeTable []tcpip.Route

	*ports.PortManager
	tcpProbeFunc TCPProbeFunc
	clock        tcpip.Clock
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
