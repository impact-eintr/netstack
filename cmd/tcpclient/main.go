package main

import (
	"fmt"
	"net"
)

func main() {
	_, err := net.Dial("tcp", "192.168.1.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return
	}
}
