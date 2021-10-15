package ports

import (
	"sync"

	"github.com/impact-eintr/netstack/tcpip"
)

const (
	// 临时端口的最小值
	anyIPAddress tcpip.Address = ""
)

// 管理端口的唯一标识: 网络层协议-传输层协议-端口号
type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// 管理端口的对象 由它来保留和释放端口
type PortManager struct {
	mu sync.RWMutex
	// 用一个map来保存被占用的端口
	allocatedPorts map[portDescriptor]bindAddresses
}

type bindAddresses map[tcpip.Address]struct{}
