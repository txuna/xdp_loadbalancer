package main

import (
	"fmt"
	"bufio"
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

	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		msg := scanner.Text()
		fmt.Println("recv:", msg)           // 서버 콘솔에 출력
		_, _ = fmt.Fprintln(c, msg)        // 클라이언트에 그대로 돌려줌
	}
	if err := scanner.Err(); err != nil {
		log.Println("read error:", err)
	}
}
