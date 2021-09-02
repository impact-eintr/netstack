package main

import (
	"github.com/impact-eintr/netstack/tcpip/link/tuntap"
)

func main() {
	tapName := "tap0"
	c := &tuntap.Config{
		tapName,
		tuntap.TAP,
	}

	fd, err := tuntap.NewNetDev(c)
	if err != nil {
		panic(err)
	}

	// 启动tap网卡
	_ = tuntap.SetLinkUp(tapName)
	// 添加ip地址
	_ = tuntap.AddIP(tapName, "192.168.1.1/24")

	buf := make([]byte, 1<<16)
	for {
	}
}
