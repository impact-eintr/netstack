package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	go func() {
		conn, err := net.Dial("tcp", "192.168.1.1:9999")
		if err != nil {
			fmt.Println("err : ", err)
			return
		}
		log.Println("连接建立")
		conn.Write([]byte("helloworld"))
		log.Println("发送了数据")
		//buf := make([]byte, 1024)
		//conn.Read(buf)
		conn.Close()
	}()

	t := time.NewTimer(1000 * time.Millisecond)
	select {
	case <-t.C:
		return
	}

}
