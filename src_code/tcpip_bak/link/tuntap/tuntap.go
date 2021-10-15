package tuntap

import (
	"errors"
	"fmt"
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
	Name string
	Mode int
}

func NewNetDev(c *Config) (fd int, err error) {
	switch c.Mode {
	case TUN:
		fd, err = newTUN(c.Name)
	case TAP:
		fd, err = newTAP(c.Name)
	default:
		err = ErrDeviceMode
		return
	}

	if err != nil {
		return
	}
	return
}

func newTUN(name string) (int, error) {
	return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)
}

func newTAP(name string) (int, error) {
	return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)
}

// 先打开一个字符串设备，通过系统调用将虚拟网卡和字符串设备fd绑定在一起
func open(name string, flags uint16) (int, error) {
	// 打开tuntap的字符设备 得到字符串设备的文件描述符
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], name) // 复制名字
	ifr.flags = flags
	// 通过ioctl系统调用，将fd和虚拟网卡驱动绑定在一起
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return -1, errno
	}
	return fd, nil

}

// 通过ip命令使系统启动该网卡
func SetLinkUp(name string) (err error) {
	// ip link set <device-name> up
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		return fmt.Errorf("%v:%v", cmdErr, string(out))
	}
	return
}

// 通过ip命令添加路由
func SetRoute(name, cidr string) (err error) {
	out, cmdErr := exec.Command("ip", "route", "add", cidr, "dev", name).CombinedOutput()
	if cmdErr != nil {
		return fmt.Errorf("%v:%v", cmdErr, string(out))
	}
	return
}

// 通过ip命令添加IP地址 ip addrr add X.X.X.X dev tap0
func AddIP(name, ip string) (err error) {
	out, cmdErr := exec.Command("ip", "addr", "add", ip, "dev", name).CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
	}
	return
}

func GetHardwareAddr(name string) (string, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		addr rawSockaddr
		_    [8]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.SIOCGIFADDR, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return "", errno
	}
	mac := ifreq.addr.Data[:6]
	return string(mac[:]), nil

}
