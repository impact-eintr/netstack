package tuntap

import (
	"errors"
	"syscall"
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

func newTun(name string) (int, error) {
	return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)

}

func newTAP(name string) (int, error) {
	return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)

}

// 先打开一个字符串设备，通过系统调用将虚拟网卡和字符串设备fd bind在一起
func open(name string, flags uint16) (int, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

}
