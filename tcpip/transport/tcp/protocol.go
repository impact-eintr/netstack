package tcp

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"netstack/waiter"
	"sync"
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

// SendBufferSizeOption allows the default, min and max send buffer sizes for
// TCP endpoints to be queried or configured.
type SendBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

// ReceiveBufferSizeOption allows the default, min and max receive buffer size
// for TCP endpoints to be queried or configured.
type ReceiveBufferSizeOption struct {
	Min     int
	Default int
	Max     int
}

const (
	ccReno  = "reno"
	ccCubic = "cubic"
)

// CongestionControlOption sets the current congestion control algorithm.
type CongestionControlOption string

type protocol struct {
	mu                         sync.Mutex
	sackEnabled                bool
	sendBufferSize             SendBufferSizeOption
	recvBufferSize             ReceiveBufferSizeOption
	congestionControl          string
	availableCongestionControl []string
	allowedCongestionControl   []string
}

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
	switch v := option.(type) {
	case SACKEnabled:
		p.mu.Lock()
		p.sackEnabled = bool(v)
		p.mu.Unlock()
		return nil

	case SendBufferSizeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}
		p.mu.Lock()
		p.sendBufferSize = v
		p.mu.Unlock()
		return nil

	case ReceiveBufferSizeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return tcpip.ErrInvalidOptionValue
		}
		p.mu.Lock()
		p.recvBufferSize = v
		p.mu.Unlock()
		return nil

	case CongestionControlOption:
		for _, c := range p.availableCongestionControl {
			if string(v) == c {
				p.mu.Lock()
				p.congestionControl = string(v)
				p.mu.Unlock()
				return nil
			}
		}
		return tcpip.ErrInvalidOptionValue
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Option implements TransportProtocol.Option.
func (p *protocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *SACKEnabled:
		p.mu.Lock()
		*v = SACKEnabled(p.sackEnabled)
		p.mu.Unlock()
		return nil

	case *SendBufferSizeOption:
		p.mu.Lock()
		*v = p.sendBufferSize
		p.mu.Unlock()
		return nil

	case *ReceiveBufferSizeOption:
		p.mu.Lock()
		*v = p.recvBufferSize
		p.mu.Unlock()
		return nil
	case *CongestionControlOption:
		p.mu.Lock()
		*v = CongestionControlOption(p.congestionControl)
		p.mu.Unlock()
		return nil
	//case *AvailableCongestionControlOption:
	//	p.mu.Lock()
	//	*v = AvailableCongestionControlOption(strings.Join(p.availableCongestionControl, " "))
	//	p.mu.Unlock()
	//	return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func init() {
	stack.RegisterTransportProtocolFactory(ProtocolName, func() stack.TransportProtocol {
		return &protocol{
			mu:                         sync.Mutex{},
			sackEnabled:                false,
			sendBufferSize:             SendBufferSizeOption{minBufferSize, DefaultBufferSize, maxBufferSize},
			recvBufferSize:             ReceiveBufferSizeOption{minBufferSize, DefaultBufferSize, maxBufferSize},
			congestionControl:          ccReno,
			availableCongestionControl: []string{ccReno, ccCubic},
			allowedCongestionControl:   []string{},
		}
	})
}
