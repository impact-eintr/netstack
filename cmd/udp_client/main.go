package main

import (
	"flag"
	"log"
	"net"
)

func main() {
	var (
		addr = flag.String("a", "192.168.1.1:9999", "udp dst address")
	)

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	var err error
	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		panic(err)
	}

	// 建立UDP连接（只是填息了目的IP和端口，并未真正的建立连接）
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		panic(err)
	}

	send := []byte("hello world")
	if _, err := conn.Write(send); err != nil {
		panic(err)
	}
	log.Printf("send: %s", string(send))

	recv := make([]byte, 32)
	rn, _, err := conn.ReadFrom(recv)
	if err != nil {
		panic(err)
	}
	log.Printf("recv: %s", string(recv[:rn]))
}
