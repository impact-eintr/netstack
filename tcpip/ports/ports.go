package ports

import (
	"math"
	"math/rand"
	"netstack/tcpip"
	"sync"
)

const (
	// 临时端口的最小值
	FirstEphemeral = 16000

	anyIPAddress tcpip.Address = ""
)

// 端口的唯一标识 : 网络层协议-传输层协议-端口号
type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// PortManager 管理端口的对象 由他来保留和释放端口
type PortManager struct {
	mu sync.RWMutex
	// 用一个map接口来保存被占用的端口
	// port:ips ipv4-tcp-80:[192.168.1.1, 192.168.1.2]
	//          ipv4-udp-9999:[192.168.10.1, 192.168.10.2]
	allocatedPorts map[portDescriptor]bindAddresses
}

// 一个IP地址的集合
type bindAddresses map[tcpip.Address]struct{}

func (b bindAddresses) isAvailable(addr tcpip.Address) bool {
	if addr == anyIPAddress {
		return len(b) == 0
	}

	if _, ok := b[anyIPAddress]; ok {
		return false
	}

	if _, ok := b[addr]; ok {
		return false
	}
	return true
}

// NewPortManager 新建一个端口管理器
func NewPortManager() *PortManager {
	return &PortManager{
		allocatedPorts: make(map[portDescriptor]bindAddresses),
	}
}

// PickEphemeralPort 从端口管理器中随机分配一个端口，并调用testPort来检测是否可用
func (s *PortManager) PickEphemeralPort(testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
	count := uint16(math.MaxUint16 - FirstEphemeral + 1)
	offset := uint16(rand.Int31n(int32(count)))

	for i := uint16(0); i < count; i++ {
		port = FirstEphemeral + (offset+i)%count
		ok, err := testPort(port)
		if err != nil {
			return 0, nil
		}
		if ok {
			return port, nil
		}
	}
	return 0, tcpip.ErrNoPortAvailable
}

// IsPortAvailable 根据参数判断该端口号是否已经被占用了
func (s *PortManager) IsPortAvailable(networks []tcpip.NetworkProtocolNumber,
	transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPortAvailableLocked(networks, transport, addr, port)
}

// 根据参数判断该端口号是否被占用
func (s *PortManager) isPortAvailableLocked(networks []tcpip.NetworkProtocolNumber,
	transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16) bool {
	for _, network := range networks { // 遍历网络协议
		desc := portDescriptor{network: network, transport: transport, port: port} // 构造端口描述符
		if addrs, ok := s.allocatedPorts[desc]; ok {                               // 检查端口描述符绑定的ip集合
			if !addrs.isAvailable(addr) { // 该集合中已经有这个ip
				return false
			}
		}
	}
	return true
}

// ReservePort 将端口和IP地址绑定在一起，这样别的程序就无法使用已经被绑定的端口。
// 如果传入的端口不为0，那么会尝试绑定该端口，若该端口没有被占用，那么绑定成功。
// 如果传人的端口等于0，那么就是告诉协议栈自己分配端口，端口管理器就会随机返回一个端口。
func (s *PortManager) ReservePort(networks []tcpip.NetworkProtocolNumber,
	transport tcpip.TransportProtocolNumber,
	addr tcpip.Address, port uint16) (reservedPort uint16, err *tcpip.Error) {
	return 0, nil
}
