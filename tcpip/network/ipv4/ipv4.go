package ipv4

import (
	"log"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/network/fragmentation"
	"netstack/tcpip/network/hash"
	"netstack/tcpip/stack"
	"sync/atomic"
)

const (
	// ProtocolName is the string representation of the ipv4 protocol name.
	ProtocolName = "ipv4"

	// ProtocolNumber is the ipv4 protocol number.
	ProtocolNumber = header.IPv4ProtocolNumber

	// maxTotalSize is maximum size that can be encoded in the 16-bit
	// TotalLength field of the ipv4 header.
	maxTotalSize = 0xffff

	// buckets is the number of identifier buckets.
	buckets = 2048
)

// IPv4 实现
type endpoint struct {
	// 网卡id
	nicid tcpip.NICID
	// 表示该endpoint的id，也是ip地址
	id stack.NetworkEndpointID
	// 链路端的表示
	linkEP stack.LinkEndpoint
	// 报文分发器
	dispatcher stack.TransportDispatcher
	// ping请求报文接收队列
	echoRequests chan echoRequest
	// ip报文分片处理器
	fragmentation *fragmentation.Fragmentation
}

// DefaultTTL is the default time-to-live value for this endpoint.
// 默认的TTL值，TTL每经过路由转发一次就会减1
func (e *endpoint) DefaultTTL() uint8 {
	return 255
}

// MTU implements stack.NetworkEndpoint.MTU. It returns the link-layer MTU minus
// the network layer max header length.
// 获取去除ipv4头部后的最大报文长度
func (e *endpoint) MTU() uint32 {
	return calculateMTU(e.linkEP.MTU())
}

// Capabilities implements stack.NetworkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.linkEP.Capabilities()
}

// NICID returns the ID of the NIC this endpoint belongs to.
func (e *endpoint) NICID() tcpip.NICID {
	return e.nicid
}

// ID returns the ipv4 endpoint ID.
// 获取该网络层端的id，也就是ip地址
func (e *endpoint) ID() *stack.NetworkEndpointID {
	return &e.id
}

// MaxHeaderLength returns the maximum length needed by ipv4 headers (and
// underlying protocols).
// 链路层和网络层的头部长度
func (e *endpoint) MaxHeaderLength() uint16 {
	return e.linkEP.MaxHeaderLength() + header.IPv4MinimumSize
}

// WritePacket writes a packet to the given destination address and protocol.
// 将传输层的数据封装加上IP头，并调用网卡的写入接口，写入IP报文
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	// 预留ip报文的空间
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	length := uint16(hdr.UsedLength() + payload.Size())
	id := uint32(0)
	// 如果报文长度大于68
	if length > header.IPv4MaximumHeaderSize+8 {
		// Packets of 68 bytes or less are required by RFC 791 to not be
		// fragmented, so we only assign ids to larger packets.
		id = atomic.AddUint32(&ids[hashRoute(r, protocol)%buckets], 1)
	}
	// ip首部编码
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: length,
		ID:          uint16(id),
		TTL:         ttl,
		Protocol:    uint8(protocol),
		SrcAddr:     r.LocalAddress,
		DstAddr:     r.RemoteAddress,
	})
	// 计算校验和和设置校验和
	ip.SetChecksum(^ip.CalculateChecksum())
	r.Stats().IP.PacketsSent.Increment()

	// 写入网卡接口
	if protocol == header.ICMPv4ProtocolNumber {
		log.Println("IP 写回ICMP报文", header.IPv4(append(ip, payload.ToView()...)))
	} else {
		logger.GetInstance().Info(logger.IP, func() {
			if payload.Size() == 0 {
				log.Printf("发送 IP 报文 %d bytes", hdr.UsedLength()+payload.Size())
			}
		})
	}
	return e.linkEP.WritePacket(r, hdr, payload, ProtocolNumber)
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
// 收到ip包的处理
func (e *endpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
	// 得到ip报文
	h := header.IPv4(vv.First())
	// 检查报文是否有效
	if !h.IsValid(vv.Size()) {
		return
	}
	logger.GetInstance().Info(logger.IP, func() {
		log.Println(h)
	})

	hlen := int(h.HeaderLength())
	tlen := int(h.TotalLength())
	vv.TrimFront(hlen)
	vv.CapLength(tlen - hlen)

	// 报文重组
	more := (h.Flags() & header.IPv4FlagMoreFragments) != 0
	// 是否需要ip重组
	if more || h.FragmentOffset() != 0 {
		// The packet is a fragment, let's try to reassemble it.
		last := h.FragmentOffset() + uint16(vv.Size()) - 1
		var ready bool
		// ip分片重组
		vv, ready = e.fragmentation.Process(hash.IPv4FragmentHash(h), h.FragmentOffset(), last, more, vv)
		if !ready {
			return
		}
	}

	// 得到传输层的协议
	p := h.TransportProtocol()
	// 如果时ICMP协议，则进入ICMP处理函数
	if p == header.ICMPv4ProtocolNumber {
		e.handleICMP(r, vv)
		return
	}
	r.Stats().IP.PacketsDelivered.Increment()
	// 根据协议分发到不同处理函数，比如协议时TCP，会进入tcp.HandlePacket
	logger.GetInstance().Info(logger.IP, func() {
		log.Printf("准备前往 UDP/TCP recv ipv4 packet %d bytes, proto: 0x%x", tlen, p)
	})
	e.dispatcher.DeliverTransportPacket(r, p, vv)
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	close(e.echoRequests)
}

// 实现NetworkProtocol接口
type protocol struct{}

// NewEndpoint creates a new ipv4 endpoint.
// 根据参数，新建一个ipv4端
func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache,
	dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	e := &endpoint{
		nicid:        nicid,
		id:           stack.NetworkEndpointID{LocalAddress: addr},
		linkEP:       linkEP,
		dispatcher:   dispatcher,
		echoRequests: make(chan echoRequest, 10),
		fragmentation: fragmentation.NewFragmentation(fragmentation.HighFragThreshold,
			fragmentation.LowFragThreshold, fragmentation.DefaultReassembleTimeout),
	}

	go e.echoReplier()

	return e, nil
}

// NewProtocol creates a new protocol ipv4 protocol descriptor. This is exported
// only for tests that short-circuit the stack. Regular use of the protocol is
// done via the stack, which gets a protocol descriptor from the init() function
// below.
func NewProtocol() stack.NetworkProtocol {
	return &protocol{}
}

// Number returns the ipv4 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv4 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv4MinimumSize
}

// ParseAddresses implements NetworkProtocol.ParseAddresses.
func (*protocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	h := header.IPv4(v)
	return h.SourceAddress(), h.DestinationAddress()
}

// SetOption implements NetworkProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// Option implements NetworkProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return tcpip.ErrUnknownProtocolOption
}

// calculateMTU calculates the network-layer payload MTU based on the link-layer
// payload mtu.
func calculateMTU(mtu uint32) uint32 {
	if mtu > maxTotalSize {
		mtu = maxTotalSize
	}
	return mtu - header.IPv4MinimumSize
}

// 用 源地址 目标地址 和 传输层协议号 进行一个哈希
func hashRoute(r *stack.Route, protocol tcpip.TransportProtocolNumber) uint32 {
	t := r.LocalAddress
	a := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = r.RemoteAddress
	b := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return hash.Hash3Words(a, b, uint32(protocol), hashIV)
}

var (
	ids    []uint32
	hashIV uint32
)

func init() {
	ids = make([]uint32, buckets)

	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i] // 初始化ids
	}
	hashIV = r[buckets]

	stack.RegisterNetworkProtocolFactory(ProtocolName, func() stack.NetworkProtocol {
		return &protocol{}
	})
}
