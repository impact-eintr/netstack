package tcpip

import (
	"errors"
	"fmt"
	"netstack/tcpip/buffer"
	"netstack/waiter"
	"reflect"
	"strings"
	"sync/atomic"
)

type Error struct {
	msg         string
	ignoreStats bool
}

func (e *Error) String() string {
	return e.msg
}

func (e *Error) IgnoreStats() bool {
	return e.ignoreStats
}

var (
	ErrUnknownProtocol       = &Error{msg: "unknown protocol"}
	ErrUnknownNICID          = &Error{msg: "unknown nic id"}
	ErrUnknownProtocolOption = &Error{msg: "unknown option for protocol"}
	ErrDuplicateNICID        = &Error{msg: "duplicate nic id"}
	ErrDuplicateAddress      = &Error{msg: "duplicate address"}
	ErrNoRoute               = &Error{msg: "no route"}
	ErrBadLinkEndpoint       = &Error{msg: "bad link layer endpoint"}
	ErrAlreadyBound          = &Error{msg: "endpoint already bound", ignoreStats: true}
	ErrInvalidEndpointState  = &Error{msg: "endpoint is in invalid state"}
	ErrAlreadyConnecting     = &Error{msg: "endpoint is already connecting", ignoreStats: true}
	ErrAlreadyConnected      = &Error{msg: "endpoint is already connected", ignoreStats: true}
	ErrNoPortAvailable       = &Error{msg: "no ports are available"}
	ErrPortInUse             = &Error{msg: "port is in use"}
	ErrBadLocalAddress       = &Error{msg: "bad local address"}
	ErrClosedForSend         = &Error{msg: "endpoint is closed for send"}
	ErrClosedForReceive      = &Error{msg: "endpoint is closed for receive"}
	ErrWouldBlock            = &Error{msg: "operation would block", ignoreStats: true}
	ErrConnectionRefused     = &Error{msg: "connection was refused"}
	ErrTimeout               = &Error{msg: "operation timed out"}
	ErrAborted               = &Error{msg: "operation aborted"}
	ErrConnectStarted        = &Error{msg: "connection attempt started", ignoreStats: true}
	ErrDestinationRequired   = &Error{msg: "destination address is required"}
	ErrNotSupported          = &Error{msg: "operation not supported"}
	ErrQueueSizeNotSupported = &Error{msg: "queue size querying not supported"}
	ErrNotConnected          = &Error{msg: "endpoint not connected"}
	ErrConnectionReset       = &Error{msg: "connection reset by peer"}
	ErrConnectionAborted     = &Error{msg: "connection aborted"}
	ErrNoSuchFile            = &Error{msg: "no such file"}
	ErrInvalidOptionValue    = &Error{msg: "invalid option value specified"}
	ErrNoLinkAddress         = &Error{msg: "no remote link address"}
	ErrBadAddress            = &Error{msg: "bad address"}
	ErrNetworkUnreachable    = &Error{msg: "network is unreachable"}
	ErrMessageTooLong        = &Error{msg: "message too long"}
	ErrNoBufferSpace         = &Error{msg: "no buffer space available"}
)

// Errors related to Subnet
var (
	errSubnetLengthMismatch = errors.New("subnet length of address and mask differ")
	errSubnetAddressMasked  = errors.New("subnet address has bits set outside the mask")
)

// Clock 提供当前的时间戳
type Clock interface {
	NowNanoseconds() int64

	NowMonotonic() int64
}

// 地址是一个字节切片，转换为表示网络节点地址的字符串。或者，在 unix 端点的情况下，它可能代表一条路径
type Address string

type AddressMask string

func (a AddressMask) String() string {
	return Address(a).String()
}

type Subnet struct {
	address Address
	mask    AddressMask
}

// NewSubnet creates a new Subnet, checking that the address and mask are the same length.
func NewSubnet(a Address, m AddressMask) (Subnet, error) {
	if len(a) != len(m) {
		return Subnet{}, errSubnetLengthMismatch
	}
	for i := 0; i < len(a); i++ {
		if a[i]&^m[i] != 0 {
			return Subnet{}, errSubnetAddressMasked
		}
	}
	return Subnet{a, m}, nil
}

// Contains returns true iff the address is of the same length and matches the
// subnet address and mask.
func (s *Subnet) Contains(a Address) bool {
	if len(a) != len(s.address) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i]&s.mask[i] != s.address[i] {
			return false
		}
	}
	return true
}

// ID returns the subnet ID.
func (s *Subnet) ID() Address {
	return s.address
}

// Bits returns the number of ones (network bits) and zeros (host bits) in the
// subnet mask.
func (s *Subnet) Bits() (ones int, zeros int) {
	for _, b := range []byte(s.mask) {
		for i := uint(0); i < 8; i++ {
			if b&(1<<i) == 0 {
				zeros++
			} else {
				ones++
			}
		}
	}
	return
}

// Prefix returns the number of bits before the first host bit.
func (s *Subnet) Prefix() int {
	for i, b := range []byte(s.mask) {
		for j := 7; j >= 0; j-- {
			if b&(1<<uint(j)) == 0 {
				return i*8 + 7 - j
			}
		}
	}
	return len(s.mask) * 8
}

// Mask returns the subnet mask.
func (s *Subnet) Mask() AddressMask {
	return s.mask
}

// LinkAddress 是一个字节切片，转换为表示链接地址的字符串。
// 它通常是一个 6 字节的 MAC 地址。
type LinkAddress string // MAC地址

func (l LinkAddress) String() string {
	if len(l) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", l[0], l[1], l[2], l[3], l[4], l[5])
	} else {
		return string(l)
	}
}

type LinkEndpointID uint64

type TransportProtocolNumber uint32

type NetworkProtocolNumber uint32

type NICID int32

// ShutdownFlags represents flags that can be passed to the Shutdown() method
// of the Endpoint interface.
type ShutdownFlags int

// Values of the flags that can be passed to the Shutdown() method. They can
// be OR'ed together.
const (
	ShutdownRead ShutdownFlags = 1 << iota
	ShutdownWrite
)

// FullAddress 传输层的完整地址
type FullAddress struct {
	NIC  NICID   // NICID
	Addr Address // IP Address
	Port uint16  // transport Port
}

func (fa FullAddress) String() string {
	return fmt.Sprintf("%d:%s:%d", fa.NIC, fa.Addr, fa.Port)
}

// Payload provides an interface around data that is being sent to an endpoint.
// This allows the endpoint to request the amount of data it needs based on
// internal buffers without exposing them. 'p.Get(p.Size())' reads all the data.
type Payload interface {
	// Get returns a slice containing exactly 'min(size, p.Size())' bytes.
	Get(size int) ([]byte, *Error)

	// Size returns the payload size.
	Size() int
}

// SlicePayload 实现了 Payload
type SlicePayload []byte

// Get implements Payload.
func (s SlicePayload) Get(size int) ([]byte, *Error) {
	if size > s.Size() {
		size = s.Size()
	}
	return s[:size], nil
}

// Size implements Payload.
func (s SlicePayload) Size() int {
	return len(s)
}

// A ControlMessages contains socket control messages for IP sockets.
//
// +stateify savable
type ControlMessages struct {
	// HasTimestamp indicates whether Timestamp is valid/set.
	HasTimestamp bool

	// Timestamp is the time (in ns) that the last packed used to create
	// the read data was received.
	Timestamp int64
}

// Endpoint is the interface implemented by transport protocols (e.g., tcp, udp)
// that exposes functionality like read, write, connect, etc. to users of the
// networking stack.
// 传输层接口
type Endpoint interface {
	// Close puts the endpoint in a closed state and frees all resources
	// associated with it.
	Close()

	// Read reads data from the endpoint and optionally returns the sender.
	//
	// This method does not block if there is no data pending. It will also
	// either return an error or data, never both.
	//
	// A timestamp (in ns) is optionally returned. A zero value indicates
	// that no timestamp was available.
	Read(*FullAddress) (buffer.View, ControlMessages, *Error)

	// Write writes data to the endpoint's peer. This method does not block if
	// the data cannot be written.
	//
	// Unlike io.Writer.Write, Endpoint.Write transfers ownership of any bytes
	// successfully written to the Endpoint. That is, if a call to
	// Write(SlicePayload{data}) returns (n, err), it may retain data[:n], and
	// the caller should not use data[:n] after Write returns.
	//
	// Note that unlike io.Writer.Write, it is not an error for Write to
	// perform a partial write.
	//
	// For UDP and Ping sockets if address resolution is required,
	// ErrNoLinkAddress and a notification channel is returned for the caller to
	// block. Channel is closed once address resolution is complete (success or
	// not). The channel is only non-nil in this case.
	Write(Payload, WriteOptions) (uintptr, <-chan struct{}, *Error)

	// Peek reads data without consuming it from the endpoint.
	//
	// This method does not block if there is no data pending.
	//
	// A timestamp (in ns) is optionally returned. A zero value indicates
	// that no timestamp was available.
	Peek([][]byte) (uintptr, ControlMessages, *Error)

	// Connect connects the endpoint to its peer. Specifying a NIC is
	// optional.
	//
	// There are three classes of return values:
	//	nil -- the attempt to connect succeeded.
	//	ErrConnectStarted/ErrAlreadyConnecting -- the connect attempt started
	//		but hasn't completed yet. In this case, the caller must call Connect
	//		or GetSockOpt(ErrorOption) when the endpoint becomes writable to
	//		get the actual result. The first call to Connect after the socket has
	//		connected returns nil. Calling connect again results in ErrAlreadyConnected.
	//	Anything else -- the attempt to connect failed.
	Connect(address FullAddress) *Error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags ShutdownFlags) *Error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(backlog int) *Error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	Accept() (Endpoint, *waiter.Queue, *Error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	//
	// An optional commit function will be executed atomically with respect
	// to binding the endpoint. If this returns an error, the bind will not
	// occur and the error will be propagated back to the caller.
	Bind(address FullAddress, commit func() *Error) *Error

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (FullAddress, *Error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (FullAddress, *Error)

	// Readiness returns the current readiness of the endpoint. For example,
	// if waiter.EventIn is set, the endpoint is immediately readable.
	Readiness(mask waiter.EventMask) waiter.EventMask

	// SetSockOpt sets a socket option. opt should be one of the *Option types.
	SetSockOpt(opt interface{}) *Error

	// GetSockOpt gets a socket option. opt should be a pointer to one of the
	// *Option types.
	GetSockOpt(opt interface{}) *Error
}

// WriteOptions contains options for Endpoint.Write.
type WriteOptions struct {
	// If To is not nil, write to the given address instead of the endpoint's
	// peer.
	To *FullAddress

	// More has the same semantics as Linux's MSG_MORE.
	More bool

	// EndOfRecord has the same semantics as Linux's MSG_EOR.
	EndOfRecord bool
}

type Route struct {
	Destination Address     // 目标地址
	Mask        AddressMask // 掩码
	Gateway     Address     // 网关
	NIC         NICID       // 使用的网卡设备
}

// Match determines if r is viable for the given destination address.
func (r *Route) Match(addr Address) bool {
	if len(addr) != len(r.Destination) {
		return false
	}

	for i := 0; i < len(r.Destination); i++ {
		if (addr[i] & r.Mask[i]) != r.Destination[i] {
			return false
		}
	}

	return true
}

// Stats 包含了网络栈的统计信息
type Stats struct {
	// TODO 需要解读
	// UnknownProtocolRcvdPackets is the number of packets received by the
	// stack that were for an unknown or unsupported protocol.
	UnknownProtocolRcvdPackets *StatCounter

	// MalformedRcvPackets is the number of packets received by the stack
	// that were deemed malformed.
	MalformedRcvdPackets *StatCounter

	// DroppedPackets is the number of packets dropped due to full queues.
	DroppedPackets *StatCounter

	// IP breaks out IP-specific stats (both v4 and v6).
	IP IPStats

	// TCP breaks out TCP-specific stats.
	TCP TCPStats

	// UDP breaks out UDP-specific stats.
	UDP UDPStats
}

// A StatCounter keeps track of a statistic.
type StatCounter struct {
	count uint64
}

// Increment adds one to the counter.
func (s *StatCounter) Increment() {
	s.IncrementBy(1)
}

// Value returns the current value of the counter.
func (s *StatCounter) Value() uint64 {
	return atomic.LoadUint64(&s.count)
}

// IncrementBy increments the counter by v.
func (s *StatCounter) IncrementBy(v uint64) {
	atomic.AddUint64(&s.count, v)
}

type IPStats struct {
	// PacketsReceived is the total number of IP packets received from the link
	// layer in nic.DeliverNetworkPacket.
	PacketsReceived *StatCounter

	// InvalidAddressesReceived is the total number of IP packets received
	// with an unknown or invalid destination address.
	InvalidAddressesReceived *StatCounter

	// PacketsDelivered is the total number of incoming IP packets that
	// are successfully delivered to the transport layer via HandlePacket.
	PacketsDelivered *StatCounter

	// PacketsSent is the total number of IP packets sent via WritePacket.
	PacketsSent *StatCounter

	// OutgoingPacketErrors is the total number of IP packets which failed
	// to write to a link-layer endpoint.
	OutgoingPacketErrors *StatCounter
}

type TCPStats struct {
	// ActiveConnectionOpenings is the number of connections opened successfully
	// via Connect.
	ActiveConnectionOpenings *StatCounter

	// PassiveConnectionOpenings is the number of connections opened
	// successfully via Listen.
	PassiveConnectionOpenings *StatCounter

	// FailedConnectionAttempts is the number of calls to Connect or Listen
	// (active and passive openings, respectively) that end in an error.
	FailedConnectionAttempts *StatCounter

	// ValidSegmentsReceived is the number of TCP segments received that the
	// transport layer successfully parsed.
	ValidSegmentsReceived *StatCounter

	// InvalidSegmentsReceived is the number of TCP segments received that
	// the transport layer could not parse.
	InvalidSegmentsReceived *StatCounter

	// SegmentsSent is the number of TCP segments sent.
	SegmentsSent *StatCounter

	// ResetsSent is the number of TCP resets sent.
	ResetsSent *StatCounter

	// ResetsReceived is the number of TCP resets received.
	ResetsReceived *StatCounter
}

type UDPStats struct {
	// PacketsReceived is the number of UDP datagrams received via
	// HandlePacket.
	PacketsReceived *StatCounter

	// UnknownPortErrors is the number of incoming UDP datagrams dropped
	// because they did not have a known destination port.
	UnknownPortErrors *StatCounter

	// ReceiveBufferErrors is the number of incoming UDP datagrams dropped
	// due to the receiving buffer being in an invalid state.
	ReceiveBufferErrors *StatCounter

	// MalformedPacketsReceived is the number of incoming UDP datagrams
	// dropped due to the UDP header being in a malformed state.
	MalformedPacketsReceived *StatCounter

	// PacketsSent is the number of UDP datagrams sent via sendUDP.
	PacketsSent *StatCounter
}

func fillIn(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		v := v.Field(i)
		switch v.Kind() {
		case reflect.Ptr:
			x := v.Addr().Interface()
			if s, ok := x.(**StatCounter); ok {
				if *s == nil {
					*s = &StatCounter{}
				}
			}
		case reflect.Struct:
			fillIn(v)
		}
	}
}

// FillIn returns a copy of s with nil fields initialized to new StatCounters.
func (s Stats) FillIn() Stats {
	fillIn(reflect.ValueOf(&s).Elem())
	return s
}

func (a Address) String() string {
	switch len(a) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", int(a[0]), int(a[1]), int(a[2]), int(a[3]))
	case 16:
		// Find the longest subsequence of hexadecimal zeros.
		start, end := -1, -1
		for i := 0; i < len(a); i += 2 {
			j := i
			for j < len(a) && a[j] == 0 && a[j+1] == 0 {
				j += 2
			}
			if j > i+2 && j-i > end-start {
				start, end = i, j
			}
		}
		var b strings.Builder
		for i := 0; i < len(a); i += 2 {
			if i == start {
				b.WriteString("::")
				i = end
				if end >= len(a) {
					break
				}
			} else if i > 0 {
				b.WriteByte(':')
			}
			v := uint16(a[i+0])<<8 | uint16(a[i+1])
			if v == 0 {
				b.WriteByte('0')
			} else {
				const digits = "0123456789abcdef"
				for i := uint(3); i < 4; i-- {
					if v := v >> (i * 4); v != 0 {
						b.WriteByte(digits[v&0xf])
					}
				}
			}
		}
		return b.String()
	default:
		return fmt.Sprintf("%s", string(a))
	}
}
