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
	ErrDeviceMode = errors.New("unspport device mode")
)

type rawSockaddr struct {
	Family uint16
	Data   [14]byte
}

// 虚拟网卡设置的配置
type Config struct {
	Name string // 网卡名
	Mode int    // 网卡模式 TUN or TAP
}

// NewNetDev 根据配置返回虚拟网卡的文件描述符
func NewNetDev(c *Config) (fd int, err error) {
	switch c.Mode {
	case TUN:
		fd, err = newTun(c.Name)
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

// SetLinkUp 让系统启动该网卡
func SetLinkUp(name string) (err error) {
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return
}

// SetRoute 通过ip命令添加路由
func SetRoute(name, cidr string) (err error) {
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return

}

// SetRoute 通过ip命令添加IP地址
func AddIP(name, ip string) (err error) {
	out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if cmdErr != nil {
		err = fmt.Errorf("%v:%v", cmdErr, string(out))
		return
	}
	return

}

func newTun(name string) (int, error) {
	return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)

}

func newTAP(name string) (int, error) {
	return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)

}

// 先打开一个字符串设备，通过系统调用将虚拟网卡和字符串设备fd bind在一起
func open(name string, flags uint16) (int, error) {
	// 打开一个字符串设备 得到自负设备的文件描述符
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  []byte
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
