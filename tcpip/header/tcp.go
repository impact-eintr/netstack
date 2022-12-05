package header

import (
	"encoding/binary"
	"fmt"
	"netstack/tcpip"
	"netstack/tcpip/seqnum"
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
	// TCP的初始序列号ISN是随机生成的
	// 如果TCP每次连接都使用固定ISN，黑客可以很方便模拟任何IP与server建立连接
	// 如果ISN是固定的，那很可能在新连接建立后，上次连接通信的报文才到达，
	// 这种情况有概率发生老报文的seq号正好是server希望收到的新连接的报文seq。这就全乱了。
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

// Options that may be present in a TCP segment.
const (
	TCPOptionEOL           = 0
	TCPOptionNOP           = 1
	TCPOptionMSS           = 2
	TCPOptionWS            = 3
	TCPOptionTS            = 8
	TCPOptionSACKPermitted = 4
	TCPOptionSACK          = 5
)

// SACKBlock 表示 sack 块的结构体
type SACKBlock struct {
	// Start indicates the lowest sequence number in the block.
	Start seqnum.Value

	// End indicates the sequence number immediately following the last
	// sequence number of this block.
	End seqnum.Value
}

// TCPOptions tcp选项结构，这个结构不表示 syn/syn-ack 报文
type TCPOptions struct {
	// TS is true if the TimeStamp option is enabled.
	TS bool

	// TSVal is the value in the TSVal field of the segment.
	TSVal uint32

	// TSEcr is the value in the TSEcr field of the segment.
	TSEcr uint32

	// SACKBlocks are the SACK blocks specified in the segment.
	SACKBlocks []SACKBlock
}

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

// ParseTCPOptions extracts and stores all known options in the provided byte
// slice in a TCPOptions structure.
func ParseTCPOptions(b []byte) TCPOptions {
	opts := TCPOptions{}
	limit := len(b)
	for i := 0; i < limit; {
		switch b[i] {
		case TCPOptionEOL: // 末尾
			i = limit
		case TCPOptionNOP: // 空值
			i++
		case TCPOptionTS: // 计时
			if i+10 > limit || (b[i+1] != 10) {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		case TCPOptionSACK:
			if i+2 > limit {
				// Malformed SACK block, just return and stop parsing.
				return opts
			}
			sackOptionLen := int(b[i+1])
			// TODO 需要添加

			i += sackOptionLen
		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return opts
			}
			i++
		}
	}
	return opts
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
|% 8v|
|             Padding             |
%v`

func (b TCP) String() string {
	return fmt.Sprintf(tcpFmt, atoi(b.SourcePort()), atoi(b.DestinationPort()),
		atoi(b.SequenceNumber()),
		atoi(b.AckNumber()),
		atoi(b.DataOffset()), "0", b.Flags(), atoi(b.WindowSize()),
		atoi(b.Checksum()), atoi(b.UrgentPtr()),
		ParseTCPOptions(b.Options()),
		b.viewPayload())
}
