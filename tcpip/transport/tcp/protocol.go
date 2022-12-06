package tcp

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"netstack/waiter"
)

const (
	// ProtocolName is the string representation of the tcp protocol name.
	ProtocolName = "tcp"

	// ProtocolNumber is the tcp protocol number.
	ProtocolNumber = header.TCPProtocolNumber
	// MinBufferSize is the smallest size of a receive or send buffer.
	minBufferSize = 4 << 10 // 4096 bytes.

	// DefaultBufferSize is the default size of the receive and send buffers.
	DefaultBufferSize = 1 << 20 // 1MB

	// MaxBufferSize is the largest size a receive and send buffer can grow to.
	maxBufferSize = 4 << 20 // 4MB
)

// SACKEnabled option can be used to enable SACK support in the TCP
// protocol. See: https://tools.ietf.org/html/rfc2018.
type SACKEnabled bool

type protocol struct{}

// Number returns the tcp protocol number.
func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

// NewEndpoint creates a new tcp endpoint.
func (*protocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, waiterQueue), nil
}

// ParsePorts returns the source and destination ports stored in the given tcp
// packet.
func (*protocol) ParsePorts(v buffer.View) (src, dst uint16, err *tcpip.Error) {
	h := header.TCP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// MinimumPacketSize returns the minimum valid tcp packet size.
func (*protocol) MinimumPacketSize() int {
	return header.TCPMinimumSize
}

func (*protocol) HandleUnknownDestinationPacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) bool {
	return false
}

// SetOption implements TransportProtocol.SetOption.
func (p *protocol) SetOption(option interface{}) *tcpip.Error {
	return nil
}

// Option implements TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	return nil
}

func init() {
	stack.RegisterTransportProtocolFactory(ProtocolName, func() stack.TransportProtocol {
		return &protocol{}
	})
}
