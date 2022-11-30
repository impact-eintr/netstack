package header

import (
	"encoding/binary"
	"fmt"
	"netstack/tcpip"
)

/*                                                                 _
|Version 4b|IHL 4b|Type of Service 8b|    Total Length 16b       |
 ----------------------------------------------------------------
|           fragment ID 16b          |R|DF|MF|Fragment Offset 13b|
 ----------------------------------------------------------------
|     TTL 8b      |    Protocol 8b   |   Header Checksum 16b     | 20 bytes
 ----------------------------------------------------------------
|                     Sorece IP Address 32b                      |
 ----------------------------------------------------------------
|                  Destination IP Address 32b                    | _
 ----------------------------------------------------------------
|               Options                           |    Padding   |
*/

const (
	versIHL  = 0
	tos      = 1
	totalLen = 2
	id       = 4
	flagsFO  = 6
	ttl      = 8
	protocol = 9
	checksum = 10
	srcAddr  = 12
	dstAddr  = 16
)

// 表示IPv4头部信息的结构体
type IPv4Fields struct {
	// IHL is the "internet header length" field of an IPv4 packet.
	// 头部长度
	IHL uint8

	// TOS is the "type of service" field of an IPv4 packet.
	// 服务区分的表示
	TOS uint8

	// TotalLength is the "total length" field of an IPv4 packet.
	// 数据报文总长
	TotalLength uint16

	// ID is the "identification" field of an IPv4 packet.
	// 标识符 注意这个ID对于每个IP报文来说是唯一的 它的每个分片共享这个ID来标识它们同属一个报文
	ID uint16

	// Flags is the "flags" field of an IPv4 packet.
	// 标签
	Flags uint8

	// FragmentOffset is the "fragment offset" field of an IPv4 packet.
	// 分片偏移
	FragmentOffset uint16

	// TTL is the "time to live" field of an IPv4 packet.
	// 存活时间
	TTL uint8

	// Protocol is the "protocol" field of an IPv4 packet.
	// 表示的传输层协议
	Protocol uint8

	// Checksum is the "checksum" field of an IPv4 packet.
	// 首部校验和
	Checksum uint16

	// SrcAddr is the "source ip address" of an IPv4 packet.
	// 源IP地址
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv4 packet.
	// 目的IP地址
	DstAddr tcpip.Address
}

type IPv4 []byte

const (
	// IPv4MinimumSize is the minimum size of a valid IPv4 packet.
	IPv4MinimumSize = 20

	// IPv4MaximumHeaderSize is the maximum size of an IPv4 header. Given
	// that there are only 4 bits to represents the header length in 32-bit
	// units, the header cannot exceed 15*4 = 60 bytes.
	IPv4MaximumHeaderSize = 60

	// IPv4AddressSize is the size, in bytes, of an IPv4 address.
	IPv4AddressSize = 4

	// IPv4ProtocolNumber is IPv4's network protocol number.
	IPv4ProtocolNumber tcpip.NetworkProtocolNumber = 0x0800

	// IPv4Version is the version of the ipv4 protocol.
	IPv4Version = 4

	// IPv4Broadcast is the broadcast address of the IPv4 procotol.
	IPv4Broadcast tcpip.Address = "\xff\xff\xff\xff"

	// IPv4Any is the non-routable IPv4 "any" meta address.
	IPv4Any tcpip.Address = "\x00\x00\x00\x00"
)

// Flags that may be set in an IPv4 packet.
const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

func IPVersion(b []byte) int {
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> 4)
}

// 首部长度说明首部有多少 32 位字（4 字节） 这个函数返回其实际占用的字节数
func (b IPv4) HeaderLength() uint8 {
	return (b[versIHL] & 0xf) * 4
}

func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[id:])
}

// Protocol returns the value of the protocol field of the ipv4 header.
func (b IPv4) Protocol() uint8 {
	return b[protocol]
}

// Flags returns the "flags" field of the ipv4 header.
func (b IPv4) Flags() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

// TTL returns the "TTL" field of the ipv4 header.
func (b IPv4) TTL() uint8 {
	return b[ttl]
}

// FragmentOffset returns the "fragment offset" field of the ipv4 header.
func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

// TotalLength returns the "total length" field of the ipv4 header.
func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[totalLen:])
}

// Checksum returns the checksum field of the ipv4 header.
func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[checksum:])
}

// SourceAddress returns the "source address" field of the ipv4 header.
func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.Address(b[srcAddr : srcAddr+IPv4AddressSize])
}

// DestinationAddress returns the "destination address" field of the ipv4
// header.
func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.Address(b[dstAddr : dstAddr+IPv4AddressSize])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv4) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.Protocol())
}

// Payload implements Network.Payload.
func (b IPv4) Payload() []byte {
	return b[b.HeaderLength():][:b.PayloadLength()]
}

// PayloadLength returns the length of the payload portion of the ipv4 packet.
func (b IPv4) PayloadLength() uint16 {
	return b.TotalLength() - uint16(b.HeaderLength())
}

// TOS returns the "type of service" field of the ipv4 header.
func (b IPv4) TOS() (uint8, uint32) {
	return b[tos], 0
}

// SetTOS sets the "type of service" field of the ipv4 header.
func (b IPv4) SetTOS(v uint8, _ uint32) {
	b[tos] = v
}

// SetTotalLength sets the "total length" field of the ipv4 header.
func (b IPv4) SetTotalLength(totalLength uint16) {
	binary.BigEndian.PutUint16(b[totalLen:], totalLength)
}

// SetChecksum sets the checksum field of the ipv4 header.
func (b IPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[checksum:], v)
}

// SetFlagsFragmentOffset sets the "flags" and "fragment offset" fields of the
// ipv4 header.
func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	binary.BigEndian.PutUint16(b[flagsFO:], v)
}

// SetSourceAddress sets the "source address" field of the ipv4 header.
func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	copy(b[srcAddr:srcAddr+IPv4AddressSize], addr)
}

// SetDestinationAddress sets the "destination address" field of the ipv4
// header.
func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	copy(b[dstAddr:dstAddr+IPv4AddressSize], addr)
}

// CalculateChecksum calculates the checksum of the ipv4 header.
func (b IPv4) CalculateChecksum() uint16 {
	return Checksum(b[:b.HeaderLength()], 0)
}

// Encode encodes all the fields of the ipv4 header.
func (b IPv4) Encode(i *IPv4Fields) {
	b[versIHL] = (4 << 4) | ((i.IHL / 4) & 0xf)
	b[tos] = i.TOS
	b.SetTotalLength(i.TotalLength)
	binary.BigEndian.PutUint16(b[id:], i.ID)
	b.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
	b[ttl] = i.TTL
	b[protocol] = i.Protocol
	b.SetChecksum(i.Checksum)
	copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr)
	copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr)
}

// EncodePartial updates the total length and checksum fields of ipv4 header,
// taking in the partial checksum, which is the checksum of the header without
// the total length and checksum fields. It is useful in cases when similar
// packets are produced.
func (b IPv4) EncodePartial(partialChecksum, totalLength uint16) {
	b.SetTotalLength(totalLength)
	checksum := Checksum(b[totalLen:totalLen+2], partialChecksum)
	b.SetChecksum(^checksum)
}

// IsValid performs basic validation on the packet.
func (b IPv4) IsValid(pktSize int) bool {
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(b.HeaderLength())
	tlen := int(b.TotalLength())
	if hlen > tlen || tlen > pktSize {
		return false
	}

	return true
}

// IsV4MulticastAddress determines if the provided address is an IPv4 multicast
// address (range 224.0.0.0 to 239.255.255.255). The four most significant bits
// will be 1110 = 0xe0.
func IsV4MulticastAddress(addr tcpip.Address) bool {
	if len(addr) != IPv4AddressSize {
		return false
	}
	return (addr[0] & 0xf0) == 0xe0
}

var ipv4Fmt string = `
|% 4s|% 4s|% 8s| % 16s|
|  % 16s|%s|%s|%s|% 11s|
| % 8s|% 8s|% 16s |
|% 32s    |
|% 32s    |
|        Options       |   Padding   |
%v
`

type Types []struct{}

func atoi[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32](i T) string {
	return fmt.Sprintf("%d", i)
}

func (b IPv4) String() string {
	for i := range b.Payload() {
		if i != int(b.PayloadLength()-1) && b.Payload()[i]^b.Payload()[i+1] != 0 {
			return fmt.Sprintf(ipv4Fmt, atoi(IPVersion(b)), atoi(b.HeaderLength()), atoi(0), atoi(b.TotalLength()),
				atoi(b.ID()), atoi(b.Flags()>>2), atoi((b.Flags()&2)>>1), atoi(b.Flags()&1), atoi(b.FragmentOffset()),
				atoi(b.TTL()), atoi(b.Protocol()), atoi(b.Checksum()),
				b.SourceAddress().String(),
				b.DestinationAddress().String(),
				b.Payload())
		}
	}
	return fmt.Sprintf(ipv4Fmt, atoi(IPVersion(b)), atoi(b.HeaderLength()), atoi(0), atoi(b.TotalLength()),
		atoi(b.ID()), atoi(b.Flags()>>2), atoi((b.Flags()&2)>>1), atoi(b.Flags()&1), atoi(b.FragmentOffset()),
		atoi(b.TTL()), atoi(b.Protocol()), atoi(b.Checksum()),
		b.SourceAddress().String(),
		b.DestinationAddress().String(),
		fmt.Sprintf("%v x %d", b.Payload()[0], b.PayloadLength()))
}
