package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":8000") // 포트 12345에서 대기
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Echo server listening on :8000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go handle(conn)
	}
}
func handle(c net.Conn) {
	defer c.Close()
	log.Println("new connection from", c.RemoteAddr())

	data := make([]byte, 4096)
	for {
		n, err := c.Read(data)
		if err != nil {
			fmt.Println(err)
			break
		}

		_ = n
		fmt.Println("recv: ", data[:n])

		_, err = c.Write([]byte("XDP IS HELL"))
		if err != nil {
			fmt.Println(err)
			break
		}
	}
}
