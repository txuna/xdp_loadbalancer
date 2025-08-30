package main

import (
	"net"

	"github.com/cilium/ebpf/link"
)

type Router struct {
	serverList []*Server
	objs       bpfObjects
	xdpProgram link.Link
	iface      *net.Interface
}

func NewRouter(ifaceName string) (*Router, error) {
	router := &Router{
		objs: bpfObjects{},
	}

	if err := loadBpfObjects(&router.objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	router.iface = iface

	router.xdpProgram, err = link.AttachXDP(link.XDPOptions{
		Program:   router.objs.XdpMain,
		Interface: router.iface.Index,
	})

	if err != nil {
		router.objs.Close()
		return nil, err
	}

	servs, err := initServers()
	if err != nil {
		router.objs.Close()
		router.xdpProgram.Close()
		return nil, err
	}

	if err := router.UpdateServer(servs); err != nil {
		return nil, err
	}

	return router, nil
}

func (r *Router) UpdateServer(servers []*Server) error {
	for i, server := range servers {
		var key uint32 = uint32(i)
		if err := r.objs.Servers.Put(&key, &bpfServerConfig{
			Ip:  server.IP,
			Mac: [6]uint8(server.Mac),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (r *Router) Close() {
	defer r.objs.Close()
	defer r.xdpProgram.Close()
}
