//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf xdp.c -- -I../headers

package main

import (
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	router, err := NewRouter(ifaceName)
	if err != nil {
		log.Fatalf("failed to create router: %s", err)
	}

	defer router.Close()

	if err := router.Ring(); err != nil {
		log.Printf("failed to ring: %s", err)
		return
	}
}
