package header

import (
	"encoding/binary"
	"fmt"
	"netstack/tcpip"
)

const (
	udpSrcPort  = 0
	udpDstPort  = 2
	udpLength   = 4
	udpChecksum = 6
)

// UDPFields contains the fields of a UDP packet. It is used to describe the
// fields of a packet that needs to be encoded.
// udp 首部字段
type UDPFields struct {
	// SrcPort is the "source port" field of a UDP packet.
	SrcPort uint16

	// DstPort is the "destination port" field of a UDP packet.
	DstPort uint16

	// Length is the "length" field of a UDP packet.
	Length uint16

	// Checksum is the "checksum" field of a UDP packet.
	Checksum uint16
}

// UDP represents a UDP header stored in a byte array.
type UDP []byte

const (
	// UDPMinimumSize is the minimum size of a valid UDP packet.
	UDPMinimumSize = 8

	// UDPProtocolNumber is UDP's transport protocol number.
	UDPProtocolNumber tcpip.TransportProtocolNumber = 17
)

/*
UDP 是 User Datagram Protocol 的简称，中文名是用户数据报协议。UDP 只在 IP 数据报服务上增加了一点功能，就是复用和分用的功能以及差错检测，UDP 主要的特点是：

1. UDP 是无连接的，即发送数据之前不需要建立连接，发送结束也不需要连接释放，因此减少了开销和发送数据之间的延时。
2. UDP 是不可靠传输，尽最大努力交付，因此不需要维护复杂的连接状态。
3. UDP 的数据报是有消息边界的，发送方发送一个报文，接收方就会完整的收到一个报文。
4. UDP 没有拥塞控制，网络出现阻塞，UDP 是无感知的，也就不会降低发送速度。
5. UDP 支持一对一，一对多，多对一，多对多的通信。
*/

/*
|source Port|destination Port|
|    Length  |  UDP Checksum |
|            Data            |
*/

// SourcePort returns the "source port" field of the udp header.
func (b UDP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[udpSrcPort:])
}

// DestinationPort returns the "destination port" field of the udp header.
func (b UDP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[udpDstPort:])
}

// Length returns the "length" field of the udp header.
func (b UDP) Length() uint16 {
	return binary.BigEndian.Uint16(b[udpLength:])
}

// Payload returns the data contained in the UDP datagram.
func (b UDP) Payload() []byte {
	return b[UDPMinimumSize:]
}

// Checksum returns the "checksum" field of the udp header.
func (b UDP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[udpChecksum:])
}

// SetSourcePort sets the "source port" field of the udp header.
func (b UDP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[udpSrcPort:], port)
}

// SetDestinationPort sets the "destination port" field of the udp header.
func (b UDP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[udpDstPort:], port)
}

// SetChecksum sets the "checksum" field of the udp header.
func (b UDP) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[udpChecksum:], checksum)
}

// CalculateChecksum calculates the checksum of the udp packet, given the total
// length of the packet and the checksum of the network-layer pseudo-header
// (excluding the total length) and the checksum of the payload.
func (b UDP) CalculateChecksum(partialChecksum uint16, totalLen uint16) uint16 {
	// Add the length portion of the checksum to the pseudo-checksum.
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	checksum := Checksum(tmp, partialChecksum)

	// Calculate the rest of the checksum.
	return Checksum(b[:UDPMinimumSize], checksum)
}

// Encode encodes all the fields of the udp header.
func (b UDP) Encode(u *UDPFields) {
	binary.BigEndian.PutUint16(b[udpSrcPort:], u.SrcPort)
	binary.BigEndian.PutUint16(b[udpDstPort:], u.DstPort)
	binary.BigEndian.PutUint16(b[udpLength:], u.Length)
	binary.BigEndian.PutUint16(b[udpChecksum:], u.Checksum)
}

var udpFmt string = `
|% 16s|% 16s|
|% 16s|% 16s|
%v
`

func (b UDP) String() string {
	for i := range b.Payload() {
		if i != int(b.Length()-8-1) && b.Payload()[i]^b.Payload()[i+1] != 0 {
			return fmt.Sprintf(udpFmt, atoi(b.SourcePort()), atoi(b.DestinationPort()),
				atoi(b.Length()), atoi(b.Checksum()),
				b.Payload())
		}
	}
	return fmt.Sprintf(udpFmt, atoi(b.SourcePort()), atoi(b.DestinationPort()),
		atoi(b.Length()), atoi(b.Checksum()),
		fmt.Sprintf("%v x %d", b.Payload()[0], b.Length()-8))
}
