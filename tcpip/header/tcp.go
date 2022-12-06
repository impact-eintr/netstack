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

// TCPSynOptions is used to return the parsed TCP Options in a syn
// segment.
// syn 报文的选项
type TCPSynOptions struct {
	// MSS is the maximum segment size provided by the peer in the SYN.
	MSS uint16

	// WS is the window scale option provided by the peer in the SYN.
	//
	// Set to -1 if no window scale option was provided.
	WS int

	// TS is true if the timestamp option was provided in the syn/syn-ack.
	TS bool

	// TSVal is the value of the TSVal field in the timestamp option.
	TSVal uint32

	// TSEcr is the value of the TSEcr field in the timestamp option.
	TSEcr uint32

	// SACKPermitted is true if the SACK option was provided in the SYN/SYN-ACK.
	SACKPermitted bool
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
	// 选项表结束选项
	TCPOptionEOL = 0
	// 空操作（nop）选项
	TCPOptionNOP = 1
	// 最大报文段长度选项
	TCPOptionMSS = 2
	// 窗口扩大因子选项
	TCPOptionWS = 3
	// 时间戳选项
	TCPOptionTS = 8
	// 选择性确认（Selective Acknowledgment，SACK）选项
	TCPOptionSACKPermitted = 4
	// SACK 实际工作的选项
	TCPOptionSACK = 5
)

const (
	// MaxWndScale is maximum allowed window scaling, as described in
	// RFC 1323, section 2.3, page 11.
	MaxWndScale = 14

	// TCPMaxSACKBlocks is the maximum number of SACK blocks that can
	// be encoded in a TCP option field.
	TCPMaxSACKBlocks = 4
)

// SACKBlock 表示 sack 块的结构体
type SACKBlock struct {
	// Start indicates the lowest sequence number in the block.
	Start seqnum.Value

	// End indicates the sequence number immediately following the last
	// sequence number of this block.
	End seqnum.Value
}

/*
  1byte    1byte        nbytes
+--------+--------+------------------+
| Kind   | Length |       Info       |
+--------+--------+------------------+
*/

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

	// 以下仅供测试之用 不对外暴露

	// MSS is the maximum segment size provided by the peer in the SYN.
	mss uint16

	// WS is the window scale option provided by the peer in the SYN.
	//
	// Set to -1 if no window scale option was provided.
	ws int

	// SACKPermitted is true if the SACK option was provided in the SYN/SYN-ACK.
	sackPermitted bool
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
		case TCPOptionMSS:
			if i+4 > limit || b[i+1] != 4 {
				return opts
			}
			mss := uint16(b[i+2])<<8 | uint16(b[i+3])
			if mss == 0 {
				return opts
			}
			opts.mss = mss
			i += 4
		case TCPOptionWS:
			if i+3 > limit || b[i+1] != 3 {
				return opts
			}
			ws := int(b[i+2])
			if ws > MaxWndScale {
				ws = MaxWndScale
			}
			opts.ws = ws
			i += 3
		case TCPOptionTS: // 计时
			if i+10 > limit || (b[i+1] != 10) {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		case TCPOptionSACKPermitted:
			if i+2 > limit || b[i+1] != 2 {
				return opts
			}
			opts.sackPermitted = true
			i += 2
		case TCPOptionSACK:
			if i+2 > limit {
				// Malformed SACK block, just return and stop parsing.
				return opts
			}
			sackOptionLen := int(b[i+1])
			numBlocks := (sackOptionLen - 2) / 8 // 去头 每个block长为8
			opts.SACKBlocks = []SACKBlock{}
			for j := 0; j < numBlocks; j++ {
				start := binary.BigEndian.Uint32(b[i+2+j*8:])
				end := binary.BigEndian.Uint32(b[i+2+j*8+4:])
				opts.SACKBlocks = append(opts.SACKBlocks, SACKBlock{
					Start: seqnum.Value(start),
					End:   seqnum.Value(end),
				})
			}

			i += sackOptionLen
		default:
			// 这里不做进一步解析 留到后面进行
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return opts
			}
			i += l
		}
	}

	return opts
}

func (opts TCPOptions) String() string {
	return fmt.Sprintf("|MSS|% 29d|\n|WS |% 29d|\n|TS |% 29v|\n|TSV|% 29d|\n|TSE|% 29d|\n|SP |% 29v|\n|SBS|%v|",
		opts.mss, opts.ws, opts.TS, opts.TSVal, opts.TSEcr, opts.sackPermitted, opts.SACKBlocks)
}

// ParseSynOptions parses the options received in a SYN segment and returns the
// relevant ones. opts should point to the option part of the TCP Header.
func ParseSynOptions(opts []byte, isAck bool) TCPSynOptions {
	synOpts := TCPSynOptions{
		// Per RFC 1122, page 85: "If an MSS option is not received at
		// connection setup, TCP MUST assume a default send MSS of 536."
		MSS: 536,
		// If no window scale option is specified, WS in options is
		// returned as -1; this is because the absence of the option
		// indicates that the we cannot use window scaling on the
		// receive end either.
		WS: -1,
	}

	limit := len(opts)
	for i := 0; i < limit; {
		switch opts[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionMSS:
			if i+4 > limit || opts[i+1] != 4 {
				return synOpts
			}
			mss := uint16(opts[i+2])<<8 | uint16(opts[i+3])
			if mss == 0 {
				return synOpts
			}
			synOpts.MSS = mss
			i += 4
		case TCPOptionWS:
			if i+3 > limit || opts[i+1] != 3 {
				return synOpts
			}
			ws := int(opts[i+2])
			if ws > MaxWndScale {
				ws = MaxWndScale
			}
			synOpts.WS = ws
			i += 3
		case TCPOptionTS:
			if i+10 > limit || opts[i+1] != 10 {
				return synOpts
			}
			synOpts.TSVal = binary.BigEndian.Uint32(opts[i+2:])
			if isAck { // ACK报文需要记录时间间隔
				// If the segment is a SYN-ACK then store the Timestamp Echo Reply
				// in the segment.
				synOpts.TSEcr = binary.BigEndian.Uint32(opts[i+6:])
			}
			synOpts.TS = true
			i += 10
		case TCPOptionSACKPermitted:
			if i+2 > limit || opts[i+1] != 2 {
				return synOpts
			}
			synOpts.SACKPermitted = true
			i += 2
		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return synOpts
			}
			l := int(opts[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return synOpts
			}
			i += l
		}
	}
	return synOpts
}

func (opts TCPSynOptions) String() string {
	return fmt.Sprintf("|%d|%d|%v|%d|%d|%v|", opts.MSS, opts.WS, opts.TS, opts.TSVal, opts.TSEcr, opts.SACKPermitted)
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
 ---------------------------------`

func (b TCP) String() string {
	return fmt.Sprintf(tcpFmt, atoi(b.SourcePort()), atoi(b.DestinationPort()),
		atoi(b.SequenceNumber()),
		atoi(b.AckNumber()),
		atoi(b.DataOffset()), "0", b.Flags(), atoi(b.WindowSize()),
		atoi(b.Checksum()), atoi(b.UrgentPtr()))
}
