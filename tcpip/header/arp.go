package header

import "netstack/tcpip"

const (
	// ARPProtocolNumber是ARP协议号，为0x0806
	ARPProtocolNumber tcpip.NetworkProtocolNumber = 0x0806

	// ARPSize是ARP报文在IPV4网络下的长度
	ARPSize = 2 + 2 + 1 + 1 + 2 + 2*6 + 2*4 // 28 Bytes
)

// ARPOP 代表ARP的操作码
type ARPOp uint16

// RFC 826 定义的操作码
const (
	// arp 请求
	ARPRequest ARPOp = 1
	// arp应答
	ARPReply ARPOp = 2
)

/*
ARP报文的封装
1. 2B 硬件类型(hard type) 硬件类型用来指代需要什么样的物理地址，如果硬件类型为 1，表示以太网地址
2. 2B 协议类型 协议类型则是需要映射的协议地址类型，如果协议类型是 0x0800，表示 ipv4 协议。
3. 1B 硬件地址长度 表示硬件地址的长度，单位字节，一般都是以太网地址的长度为 6 字节。
4. 1B 协议地址长度： 表示协议地址的长度，单位字节，一般都是 ipv4 地址的长度为 4 字节。
5. 2B 操作码 这些值用于区分具体操作类型，因为字段都相同，所以必须指明操作码，不然连请求还是应答都分不清。
         1=>ARP 请求, 2=>ARP 应答，3=>RARP 请求，4=>RARP 应答。
6. 6B 源硬件地址 源物理地址，如02:f2:02:f2:02:f2
7. 4B 源协议地址 源协议地址，如192.168.0.1
8. 6B 目标硬件地址 目标物理地址，如03:f2:03:f2:03:f2
9. 4B 目标协议地址 目标协议地址，如 192.168.0.2
*/
type ARP []byte

// 从报文中得到硬件类型
func (a ARP) hardwareAddressSpace() uint16 { return uint16(a[0])<<8 | uint16(a[1]) }

// 从报文中得到协议类型
func (a ARP) protocolAddressSpace() uint16 { return uint16(a[2])<<8 | uint16(a[3]) }

// 从报文中得到硬件地址的长度
func (a ARP) hardwareAddressSize() int { return int(a[4]) }

// 从报文中得到协议的地址长度
func (a ARP) protocolAddressSize() int { return int(a[5]) }

// Op从报文中得到arp操作码.
func (a ARP) Op() ARPOp { return ARPOp(a[6])<<8 | ARPOp(a[7]) }

// SetOp设置arp操作码.
func (a ARP) SetOp(op ARPOp) {
	a[6] = uint8(op >> 8)
	a[7] = uint8(op)
}

// SetIPv4OverEthernet设置IPV4网络在以太网中arp报文的硬件和协议信息.
func (a ARP) SetIPv4OverEthernet() {
	a[0], a[1] = 0, 1       // htypeEthernet
	a[2], a[3] = 0x08, 0x00 // IPv4ProtocolNumber
	a[4] = 6                // macSize
	a[5] = uint8(IPv4AddressSize)
}

// HardwareAddressSender从报文中得到arp发送方的硬件地址
func (a ARP) HardwareAddressSender() []byte {
	const s = 8
	return a[s : s+6]
}

// ProtocolAddressSender从报文中得到arp发送方的协议地址，为ipv4地址
func (a ARP) ProtocolAddressSender() []byte {
	const s = 8 + 6   // 8 是arp的协议头部 6是本机MAC
	return a[s : s+4] // 本机IP
}

// HardwareAddressTarget从报文中得到arp目的方的硬件地址
func (a ARP) HardwareAddressTarget() []byte {
	const s = 8 + 6 + 4 // 8是arp协议头部 6 是本机MAC 4是本机ip
	return a[s : s+6]   // 目标MAC
}

// ProtocolAddressTarget从报文中得到arp目的方的协议地址，为ipv4地址
func (a ARP) ProtocolAddressTarget() []byte {
	const s = 8 + 6 + 4 + 6 // 8是arp协议头部 6 是本机MAC 4是本机ip 6是目标MAC
	return a[s : s+4]       // 目标IP
}

// IsValid检查arp报文是否有效
func (a ARP) IsValid() bool {
	// 比arp报文的长度小，返回无效
	if len(a) < ARPSize {
		return false
	}
	const htypeEthernet = 1
	const macSize = 6
	// 是否以太网、ipv4、硬件和协议长度都对
	return a.hardwareAddressSpace() == htypeEthernet &&
		a.protocolAddressSpace() == uint16(IPv4ProtocolNumber) &&
		a.hardwareAddressSize() == macSize &&
		a.protocolAddressSize() == IPv4AddressSize
}
