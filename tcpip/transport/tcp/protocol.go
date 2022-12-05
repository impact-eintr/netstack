package tcp

import "netstack/tcpip/header"

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
