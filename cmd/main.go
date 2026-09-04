package main

import (
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/joho/godotenv"

	"xdp-sniffer/cmd/socket"
	"xdp-sniffer/cmd/xdp"
)

func main() {
	loadEnvironment()
	rlimit.RemoveMemlock()
	if len(os.Args) < 2 {
		log.Fatal("usage: xdp-sniffer [xdp|socket]")
	}

	switch os.Args[1] {

	case "xdp":
		xdp.Run()

	case "socket":
		socket.Run()

	default:
		log.Fatal("unknown mode")
	}
}

func loadEnvironment() {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("loading .env: %v", err)
	}
}
