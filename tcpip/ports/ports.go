package ports

import (
	"netstack/tcpip"
	"sync"
)

// 端口的唯一标识 : 网络层协议-传输层协议-端口号
type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// 一个IP地址的集合
type bindAddresses map[tcpip.Address]struct{}

// 管理端口的对象 由他来保留和释放端口
type PortManager struct {
	mu sync.RWMutex
	// 用一个map接口来保存被占用的端口
	allocatedPorts map[portDescriptor]bindAddresses
}
