package header

import (
	"encoding/binary"

	"github.com/impact-eintr/netstack/tcpip"
)

// 以太网帧头部信息的偏移量
const (
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

// 表示链路层以太网帧的头部
type EthernetFields struct {
	// 源地址
	SrcAddr tcpip.LinkAddress
	// 目标地址
	DstAddr tcpip.LinkAddress
	// 协议类型
	Type tcpip.NetworkProtocolNumber
}

// 以太网数据包的封装
type Ethernet []byte

const (
	// 以太网帧最小的长度
	EthernetMinimumSize = 14
	// 以太网帧的长度
	EthernetAddressSize = 6
)

// 从帧头部获取源地址
func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

// 从帧头部获取目的地址
func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

// 从帧头部获取协议类型
func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

// Encode根据传入的帧头部信息编码成Ethernet二进制形式
func (b Ethernet) Encode(e *EthernetFields) {
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)
}
