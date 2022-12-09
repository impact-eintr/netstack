package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "192.168.1.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return
	}
	//buf := make([]byte, 1024)
	//conn.Read(buf)
	if err = conn.Close(); err != nil {
		log.Fatal(err)
	}
}
