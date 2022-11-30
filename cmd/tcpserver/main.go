package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	_, err := net.Listen("tcp", "192.168.1.1:9999")
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
}
