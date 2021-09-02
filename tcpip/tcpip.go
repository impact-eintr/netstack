package tcpip

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
	ErrUnknowProtovol       = &Error{msg: "unknown protocol"}
	ErrUnknowNICID          = &Error{msg: "unknown nic id"}
	ErrUnknowProtocolOption = &Error{msg: "unknown option for protocol"}
	ErrDuplicateNICID       = &Error{msg: "duplicate nic id"}
	ErrDuplicateAddress     = &Error{msg: "duplicate address"}
	ErrNoRoute              = &Error{msg: "no route"}
	ErrBadLinkEndPoint      = &Error{msg: "bad link layer endpoint"}
	ErrAlreadyBound         = &Error{msg: "endpoint already bound", ignoreStats: true}
	ErrInvalidEndpointState = &Error{msg: "endpoint is in invalid state"}
	ErrAlreadConnecting     = &Error{msg: "endpoint is already connecting", ignoreStats: true}
	ErrAlreadConnected      = &Error{msg: "endpoint is already connected", ignoreStats: true}
	ErrNoPortAvailable      = &Error{msg: "no port are available"}
	ErrPortInUse            = &Error{msg: "port is in use"}
	ErrBadLocalAddress = &
)
