package ipv4

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
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
	// TODO 需要添加
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
	return nil
}

// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
// 收到ip包的处理
func (e *endpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
}

// 实现NetworkProtocol接口
type protocol struct{}

// NewEndpoint creates a new ipv4 endpoint.
// 根据参数，新建一个ipv4端
func (p *protocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache,
	dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	e := &endpoint{
		nicid:  nicid,
		id:     stack.NetworkEndpointID{LocalAddress: addr},
		linkEP: linkEP,
	}

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
	//h := header.IPv4(v)
	//return h.SourceAddress(), h.DestinationAddress()
	return "", ""
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

func init() {
	stack.RegisterNetworkProtocolFactory(ProtocolName, func() stack.NetworkProtocol {
		return &protocol{}
	})
}
