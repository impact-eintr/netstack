package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	go func() {
		_, err := net.Dial("tcp", "192.168.1.1:9999")
		if err != nil {
			fmt.Println("err : ", err)
			return
		}
	}()

	t := time.NewTimer(500 * time.Millisecond)
	select {
	case <-t.C:
		return
	}

}
