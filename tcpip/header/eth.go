package header

import (
	"encoding/binary"
	"netstack/tcpip"
)

const (
	dstMAC  = 0
	srcMAC  = 6
	ethType = 12
)

type EthernetFields struct {
	// 源地址
	SrcAddr tcpip.LinkAddress

	// 目标地址
	DstAddr tcpip.LinkAddress

	// 协议类型
	// Type = 0x8000 IPv4 Type = 0x8060 = ARP
	Type tcpip.NetworkProtocolNumber
}

// Ethernet以太网数据包的封装
type Ethernet []byte

const (
	// EthernetMinimumSize以太网帧最小的长度
	EthernetMinimumSize = 14 // 6 + 6 + 2

	// EthernetAddressSize以太网地址的长度
	EthernetAddressSize = 6
)

// SourceAddress从帧头部中得到源地址
func (b Ethernet) SourceAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[srcMAC:][:EthernetAddressSize])
}

// DestinationAddress从帧头部中得到目的地址
func (b Ethernet) DestinationAddress() tcpip.LinkAddress {
	return tcpip.LinkAddress(b[dstMAC:][:EthernetAddressSize])
}

// Type从帧头部中得到协议类型
func (b Ethernet) Type() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(b[ethType:]))
}

// Encode根据传入的帧头部信息编码成Ethernet二进制形式，注意Ethernet应先分配好内存
func (b Ethernet) Encode(e *EthernetFields) {
	// [6]byte{dst}[6]byte{src}[2]byte{type}
	binary.BigEndian.PutUint16(b[ethType:], uint16(e.Type))
	copy(b[srcMAC:][:EthernetAddressSize], e.SrcAddr)
	copy(b[dstMAC:][:EthernetAddressSize], e.DstAddr)
}
