package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

/*
Client -> LB -> (Server1, Server2)
*/
type Server struct {
	IP   uint32 // --> u32
	Port uint16 // --> u16
	Mac  []byte // --> u8
	Name string
}

func NewServer(ipStr, macStr, name string, port uint16) (*Server, error) {
	server := &Server{
		Name: name,
	}

	// ip := net.ParseIP(ipStr)
	// if ip == nil {
	// 	return nil, fmt.Errorf("could not parse ip: %s", ipStr)
	// }
	// server.IP = binary.BigEndian.Uint32(ip.To4())

	ip, err := InetPton4ToUint32(ipStr)
	if err != nil {
		return nil, err
	}

	server.IP = ip
	server.Port = Ntohs(port)

	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil, err
	}
	server.Mac = mac[:]

	return server, nil
}
func initServers() ([]*Server, error) {
	// create new server
	servs := make([]*Server, 0)

	srv, err := NewServer("10.201.0.5", "de:ad:be:ef:00:05", "Python A", 8000)
	if err != nil {
		return nil, err
	}

	servs = append(servs, srv)

	// srv, err = NewServer("10.0.0.3", "DE:AD:BE:EF:00:03", "Python B")
	// if err != nil {
	// 	return nil, err
	// }

	// servs = append(servs, srv)
	return servs, nil
}

func InetPton4ToUint32(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %s", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}
