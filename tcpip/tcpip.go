package tcpip


type Error struct {
	msg string
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



// LinkAddress 是一个字节切片，转换为表示链接地址的字符串。
// 它通常是一个 6 字节的 MAC 地址。
type LinkAddress string // MAC地址

type NetworkProtocolNumber uint32
