package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	done := make(chan int, 1)

	go func() {
		l, err := net.Listen("tcp", "0.0.0.0:9999")
		if err != nil {
			panic(err)
		}
		done <- 1
		for {
			conn, err := l.Accept()
			if err != nil {
				panic(err)
			}

			go func(net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf);err != nil{
						log.Println(err)
						break
					}
					fmt.Println(string(buf))
				}
				conn.Write([]byte("Bye Client"))
			}(conn)
		}
	}()

	go func() {
		<-done
		conn, err := net.Dial("tcp", "127.0.0.1:9999")
		if err != nil {
			fmt.Println("err : ", err)
			return
		}
		conn.Write([]byte("hello world"))

		if err = conn.Close(); err != nil {
			log.Fatal(err)
		}
		log.Println("测试")
		buf := make([]byte, 1024)
		if _, err := conn.Read(buf);err != nil{
			log.Println(err)
		}
	}()

	select{}
}
