package tcpip

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

type Error struct {
	msg         string
	ignoreStats bool
}

func (err *Error) String() string {
	return err.msg
}

func (err *Error) IgnoreStats() bool {
	return err.ignoreStats
}

var (
	ErrUnknowProtovol        = &Error{msg: "unknown protocol"}
	ErrUnknowNICID           = &Error{msg: "unknown nic id"}
	ErrUnknowProtocolOption  = &Error{msg: "unknown option for protocol"}
	ErrDuplicateNICID        = &Error{msg: "duplicate nic id"}
	ErrDuplicateAddress      = &Error{msg: "duplicate address"}
	ErrNoRoute               = &Error{msg: "no route"}
	ErrBadLinkEndPoint       = &Error{msg: "bad link layer endpoint"}
	ErrAlreadyBound          = &Error{msg: "endpoint already bound", ignoreStats: true}
	ErrInvalidEndpointState  = &Error{msg: "endpoint is in invalid state"}
	ErrAlreadyConnecting     = &Error{msg: "endpoint is already connecting", ignoreStats: true}
	ErrAlreadyConnected      = &Error{msg: "endpoint is already connected", ignoreStats: true}
	ErrNoPortAvailable       = &Error{msg: "no port are available"}
	ErrPortInUse             = &Error{msg: "port is in use"}
	ErrBadLocalAddress       = &Error{msg: "bad local address"}
	ErrClosedForSend         = &Error{msg: "endpoint is closed for send"}
	ErrClosedForReceive      = &Error{msg: "endpoint is closed for receive"}
	ErrWouldBlock            = &Error{msg: "operation would block", ignoreStats: true}
	ErrConnectionRefused     = &Error{msg: "connection was refused"}
	ErrTimeout               = &Error{msg: "operation timed out"}
	ErrAborted               = &Error{msg: "operation aborted"}
	ErrConnectStarted        = &Error{msg: "connection address is required"}
	ErrDestinationRequired   = &Error{msg: "destination address is required"}
	ErrNotSupported          = &Error{msg: "operation not supported"}
	ErrQueueSizeNotSupported = &Error{msg: "queue size querying not supported"}
	ErrNotConnected          = &Error{msg: "endpoint not connected"}
	ErrConnectionReset       = &Error{msg: "connection reset by peer"}
	ErrConnectionAborted     = &Error{msg: "connection aborted"}
	ErrNoSuchFile            = &Error{msg: "invalid option value specified"}
	ErrNoLinkAddress         = &Error{msg: "no remote link address"}
	ErrBadAddress            = &Error{msg: "bad adress"}
	ErrNetworkUnreachable    = &Error{msg: "network is unreachable"}
	ErrMessageTooLong        = &Error{msg: "message too long"}
	ErrNoBufferSpace         = &Error{msg: "no buffer space available"}
)

type LinkAddress string

func (a LinkAddress) String() string {
	switch len(a) {
	case 6:
		// MAC地址的格式 6位 4bit的十六进制数
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5])
	default:
		return fmt.Sprintf("%x", []byte(a))
	}
}

// aa:bb:cc:dd:ee:ff aa-bb-cc-dd-ee-ff
func ParseMACAddress(s string) (LinkAddress, error) {
	parts := strings.FieldsFunc(s, func(c rune) bool {
		return c == ':' || c == '-'
	})

	log.Println(parts)

	if len(parts) != 6 {
		return "", fmt.Errorf("inconsistent parts: %s", s)
	}
	addr := make([]byte, 0, len(parts))
	for _, part := range parts {
		u, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex digits: %s", s)
		}
		addr = append(addr, byte(u))
	}
	return LinkAddress(addr), nil

}

type NetworkProtocolNumber uint32
type TransportProtocolNumber uint32

type Address string

func (a Address) String() string {
	return ""
}

type ProtocolAddr struct {
	Protocol NetworkProtocolNumber
	Address  Address
}

type LinkEndpointID uint64

type Stats struct {
	UnknowProtocolRcvdPackets *StatCounter
	MalformedRcvdPackets      *StatCounter
	DroppedPackets            *StatCounter
	IP                        IPStats
	TCP                       TCPStats
	UDP                       UDPStats
}

type StatCounter struct {
	count uint64
}

type IPStats struct {
	PacketsReceived        *StatCounter
	InvalidAddressReceived *StatCounter
	PacketsDelivered       *StatCounter
	PacketsSent            *StatCounter
	OutgoingPacketErrors   *StatCounter
}

type TCPStats struct {
	ActiveConnectionOpenings  *StatCounter
	PassiveConnectionOpenings *StatCounter
	FailedConnectionAttempts  *StatCounter
	ValidSegmentReveived      *StatCounter
	InvalidSegmentReveived    *StatCounter

	SegmentsSents  *StatCounter
	ResetsSent     *StatCounter
	ResetsReceived *StatCounter
}

type UDPStats struct {
	PacketReceived           *StatCounter
	UnknownPortErrors        *StatCounter
	ReceiveBufferErrors      *StatCounter
	MalformedPacketsReceived *StatCounter
	PacketsSent              *StatCounter
}

// FullAddress 表示完整的传输节点地址，这是 Connect() 和 Bind() 方法所要求的
type FullAddress struct {
	NIC  NICID   // NIC 是这个地址所指的 NIC 的 ID
	Addr Address // 网络地址
	Port uint16  // 传输层端口
}

type NICID int32

// Route 是路由表中的一行。它指定应通过哪些 NIC（和网关）组路由数据包。
// 如果屏蔽的目标地址与行中的目标地址匹配，则该行被认为是可行的
type Route struct {
	Destination Address
	// 掩码指定目标地址和目标地址的哪些位必须匹配才能使该行可行
	Mask    AddressMask
	Gateway Address
	NIC     NICID
}

type AddressMask string

func (a AddressMask) String() string {
	return Address(a).String()
}

type Subnet struct {
	address Address
	mask    AddressMask
}

// 提供现在时刻的接口
type Clock interface {
	NowNanoseconds() int64
	NowMonoseconds() int64
}
