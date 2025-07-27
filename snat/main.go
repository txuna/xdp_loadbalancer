package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf xdp.c -- -I../headers

type backend struct {
	host string
	mac  string
	port int
}

var backends []backend

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	backends = make([]backend, 0)
	if err := UpdateBackend(&objs); err != nil {
		log.Fatalf("update backend")
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLb,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}

	defer l.Close()

	log.Printf("Attached XDP Loadbalancer program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")
}

func UpdateBackend(objs *bpfObjects) error {
	backends = append(backends, backend{
		host: "10.0.0.2",
		port: 9988,
		mac:  "de:ad:be:ef:00:02",
	})

	backends = append(backends, backend{
		host: "10.0.0.3",
		port: 9988,
		mac:  "de:ad:be:ef:00:03",
	})

	for i, backend := range backends {
		config, err := NewBackendConfig(backend.host, backend.mac, uint16(backend.port))
		if err != nil {
			return err
		}
		objs.Backends.Put(&i, config)
	}

	return nil
}

func NewBackendConfig(host, macStr string, port uint16) (*bpfBackendConfig, error) {
	ip, err := ipToUint32BE(host)
	if err != nil {
		return nil, err
	}

	mac, err := macToUint8Slice(macStr)
	if err != nil {
		return nil, err
	}

	return &bpfBackendConfig{
		Ip:   ip,
		Port: portToUint16BE(port),
		Mac:  [6]uint8(mac),
	}, nil
}

func ipToUint32BE(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	// Big-endian 변환
	return binary.BigEndian.Uint32(ip), nil
}

func portToUint16BE(port uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], port)
	return binary.BigEndian.Uint16(buf[:])
}

func macToUint8Slice(macStr string) ([]uint8, error) {
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address: %v", err)
	}
	if len(hwAddr) != 6 {
		return nil, fmt.Errorf("invalid MAC length: %d bytes", len(hwAddr))
	}

	// 명시적으로 []uint8로 변환
	macBytes := make([]uint8, 6)
	copy(macBytes, hwAddr)
	return macBytes, nil
}
