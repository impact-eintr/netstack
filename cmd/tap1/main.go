package main

import (
	"log"
	"netstack/tcpip/link/rawfile"
	"netstack/tcpip/link/tuntap"
)

func main() {
	tapName := "tap0"
	c := &tuntap.Config{Name: tapName, Mode: tuntap.TAP}
	fd, err := tuntap.NewNetDev(c)
	if err != nil {
		panic(err)
	}

	// 启动tap网卡
	_ = tuntap.SetLinkUp(tapName)
	//_ = tuntap.AddIP(tapName, "192.168.1.1/24")
	_ = tuntap.SetRoute(tapName, "192.168.1.0/24") // 其实在链路层通信，是可以不需要 ip 地址的
	log.Println("启动tap网卡", tapName, "192.169.1.1/24")

	buf := make([]byte, 1<<16)
	for {
		rn, err := rawfile.BlockingRead(fd, buf)
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("read %d bytes", rn)
	}
}
