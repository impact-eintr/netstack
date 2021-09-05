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
type Address string

type ProtocolAddr struct {
	Protocol NetworkProtocolNumber
	Address  Address
}

type LinkEndpointID uint64
