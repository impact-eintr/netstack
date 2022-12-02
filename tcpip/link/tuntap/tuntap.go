package tuntap

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	TUN = 1
	TAP = 2
)

var (
	ErrDeviceMode = errors.New("unsupport device mode")
)

type rawSockaddr struct {
	Family uint16
	Data   [14]byte
}

type Config struct {
	Name string // 网卡名
	Mode int    // 网卡模式 TUN or TAP
}

// NewNetDev根据配置返回虚拟网卡的文件描述符
func NewNetDev(c *Config) (fd int, err error) {
	switch c.Mode {
	case TUN:
		fd, err = newTun(c.Name)
	case TAP:
		fd, err = newTap(c.Name)
	default:
		err = ErrDeviceMode
		return
	}
	if err != nil {
		return
	}
	return
}

// TUN 工作在第二层
func newTun(name string) (int, error) {
	return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)
}

// TAP工作在第三层
func newTap(name string) (int, error) {
	return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)
}

func open(name string, flags uint16) (int, error) {
	// 打开tuntap 设备
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], name)
	ifr.flags = flags
	// 通过ioctl系统调用 将fd和虚拟网卡驱动绑定在一起
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return -1, errno
	}
	return fd, nil
}

// SetLinkUp 让系统启动该网卡 ip link set tap0 up
func SetLinkUp(name string) (err error) {
	// ip link set <device-name> up
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

// SetRoute 通过ip命令添加路由
func SetRoute(name, cidr string) (err error) {
	// ip route add 192.168.1.0/24 dev tap0
	out, cmdErr := exec.Command("ip", "route", "add", cidr, "dev", name).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

// SetBridge 开启并设置网桥 通过网桥进行通信
func SetBridge(bridge, tap, addr string) (err error) {
	// ip link add br0 type bridge
	out, cmdErr := exec.Command("ip", "link", "add", bridge, "type", "bridge").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	out, cmdErr = exec.Command("ip", "link", "set", "dev", bridge, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	// ifconfig br0 192.168.1.66 netmask 255.255.255.0 up
	out, cmdErr = exec.Command("ifconfig", bridge, addr, "netmask", "255.255.255.0", "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	// ip link seteth0 master br0
	out, cmdErr = exec.Command("ip", "link", "set", "eth0", "master", bridge).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	// ip link set tap0 master br0
	out, cmdErr = exec.Command("ip", "link", "set", tap, "master", bridge).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	return
}

func RemoveBridge(bridge string) (err error) {

	out, cmdErr := exec.Command("ip", "link", "set", "dev", bridge, "down").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}

	// ip link add br0 type bridge
	out, cmdErr = exec.Command("ip", "link", "del", bridge, "type", "bridge").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		log.Println(err)
	}
	return
}

// AddIP 通过ip命令添加IP地址
func AddIP(name, ip string) (err error) {
	// ip addr add 192.168.1.1 dev tap0
	out, cmdErr := exec.Command("ip", "addr", "add", ip, "dev", name).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

func GetHardwareAddr(name string) (string, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0) // 新建socket文件
	if err != nil {
		return "", nil
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		addr rawSockaddr
		_    [8]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFHWADDR,
		uintptr(unsafe.Pointer(&ifreq))) // 获取硬件地址
	if errno != 0 {
		return "", errno
	}

	mac := ifreq.addr.Data[:6]
	return string(mac[:]), nil
}
