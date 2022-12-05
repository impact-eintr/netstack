package header

import (
	"encoding/binary"
	"fmt"
	"netstack/tcpip"
)

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// TCPFields contains the fields of a TCP packet. It is used to describe the
// fields of a packet that needs to be encoded.
// tcp首部字段
type TCPFields struct {
	// SrcPort is the "source port" field of a TCP packet.
	SrcPort uint16

	// DstPort is the "destination port" field of a TCP packet.
	DstPort uint16

	// SeqNum is the "sequence number" field of a TCP packet.
	SeqNum uint32

	// AckNum is the "acknowledgement number" field of a TCP packet.
	AckNum uint32

	// DataOffset is the "data offset" field of a TCP packet.
	DataOffset uint8

	// Flags is the "flags" field of a TCP packet.
	Flags uint8

	// WindowSize is the "window size" field of a TCP packet.
	WindowSize uint16

	// Checksum is the "checksum" field of a TCP packet.
	Checksum uint16

	// UrgentPointer is the "urgent pointer" field of a TCP packet.
	UrgentPointer uint16
}

const (
	srcPort     = 0
	dstPort     = 2
	seqNum      = 4
	ackNum      = 8
	dataOffset  = 12
	tcpFlags    = 13
	winSize     = 14
	tcpChecksum = 16
	urgentPtr   = 18
)

// TCP represents a TCP header stored in a byte array.
type TCP []byte

const (
	// TCPMinimumSize is the minimum size of a valid TCP packet.
	TCPMinimumSize = 20

	// TCPProtocolNumber is TCP's transport protocol number.
	TCPProtocolNumber tcpip.TransportProtocolNumber = 6
)

// SourcePort returns the "source port" field of the tcp header.
func (b TCP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[srcPort:])
}

// DestinationPort returns the "destination port" field of the tcp header.
func (b TCP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[dstPort:])
}

// SequenceNumber returns the "sequence number" field of the tcp header.
func (b TCP) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(b[seqNum:])
}

// AckNumber returns the "ack number" field of the tcp header.
func (b TCP) AckNumber() uint32 {
	return binary.BigEndian.Uint32(b[ackNum:])
}

// DataOffset returns the "data offset" field of the tcp header.
func (b TCP) DataOffset() uint8 {
	return (b[dataOffset] >> 4) * 4 // 以32bits为单位 最小为5 20bytes
}

// Payload returns the data in the tcp packet.
func (b TCP) Payload() []byte {
	return b[b.DataOffset():]
}

// TCPViewSize TCP报文概览长度
const TCPViewSize = IPViewSize - TCPMinimumSize

func (b TCP) viewPayload() []byte {
	if len(b.Payload())-int(b.DataOffset()) < TCPViewSize {
		return b.Payload()
	}
	return b[b.DataOffset():][:TCPViewSize]
}

// Flags returns the flags field of the tcp header.
func (b TCP) Flags() uint8 {
	return b[tcpFlags]
}

// WindowSize returns the "window size" field of the tcp header.
func (b TCP) WindowSize() uint16 {
	return binary.BigEndian.Uint16(b[winSize:])
}

// Checksum returns the "checksum" field of the tcp header.
func (b TCP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[tcpChecksum:])
}

// UrgentPtr returns the "urgentptr" field of the tcp header.
func (b TCP) UrgentPtr() uint16 {
	return binary.BigEndian.Uint16(b[urgentPtr:])
}

// SetSourcePort sets the "source port" field of the tcp header.
func (b TCP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[srcPort:], port)
}

// SetDestinationPort sets the "destination port" field of the tcp header.
func (b TCP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[dstPort:], port)
}

// SetChecksum sets the checksum field of the tcp header.
func (b TCP) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[tcpChecksum:], checksum)
}

// Options returns a slice that holds the unparsed TCP options in the segment.
func (b TCP) Options() []byte {
	return b[TCPMinimumSize:b.DataOffset()]
}

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

var tcpFmt string = `
|% 16s|% 16s|
|% 32s |
|% 32s |
|% 4s|% 4s|%06b|% 16s|
|% 16s|% 16s|
|      Options      |   Padding   |
%v
`

func (b TCP) String() string {
	return fmt.Sprintf(tcpFmt, atoi(b.SourcePort()), atoi(b.DestinationPort()),
		atoi(b.SequenceNumber()),
		atoi(b.AckNumber()),
		atoi(b.DataOffset()), "0", b.Flags(), atoi(b.WindowSize()),
		atoi(b.Checksum()), atoi(b.UrgentPtr()),
		b.viewPayload())
}
