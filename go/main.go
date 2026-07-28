package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../xdp.ebpf.c

func main() {
	var objs xdpObjects

	err := loadXdpObjects(&objs, nil)

	if err != nil {
		log.Fatal(err)
	}

	defer objs.Close()

	iface, err := net.InterfaceByName("wlp3s0")

	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal(err)
	}

	defer l.Close()

	log.Printf("XDP Program attached to %s", iface.Name)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

	log.Println("\nDetaching XDP...")
}
