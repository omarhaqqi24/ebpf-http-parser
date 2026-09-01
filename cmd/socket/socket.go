package socket

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux sockethttp ../../bpf/socket_http.ebpf.c -- -I../bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	serverAddress = "127.0.0.1:8000"
)

/*
 * =========================================================
 * Event
 *
 * Must match socket_event in socket_http.bpf.c
 * =========================================================
 */

type socketEvent struct {
	Timestamp    uint64
	SocketCookie uint64
	DataLen      uint32
	Data         [256]byte
}

// Run attaches the SOCKMAP programs and starts the TCP server.
func Run() {
	objs, reader, err := setupSocketHTTP()
	if err != nil {
		log.Fatalf("setting up socket HTTP monitor: %v", err)
	}

	defer objs.Close()
	defer reader.Close()

	serveTCP(reader, objs.SockMap)
}

// setupSocketHTTP loads the eBPF programs, attaches them to the SOCKMAP, and
// creates the reader used to receive socket events.
func setupSocketHTTP() (*sockethttpObjects, *ringbuf.Reader, error) {
	objs := &sockethttpObjects{}
	if err := loadSockethttpObjects(objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	if err := attachSockmapProgram(
		objs.SocketStreamParser,
		objs.SockMap,
		ebpf.AttachSkSKBStreamParser,
	); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attaching stream parser: %w", err)
	}

	if err := attachSockmapProgram(
		objs.SocketStreamVerdict,
		objs.SockMap,
		ebpf.AttachSkSKBStreamVerdict,
	); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attaching stream verdict: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	log.Println("SK_SKB stream parser attached")
	log.Println("SK_SKB stream verdict attached")
	return objs, reader, nil
}

// serveTCP receives eBPF events and accepts TCP connections until the process
// is stopped.
func serveTCP(reader *ringbuf.Reader, sockMap *ebpf.Map) {
	closeReaderOnSignal(reader)

	listener, err := net.Listen("tcp", serverAddress)

	if err != nil {
		log.Fatalf("starting TCP server: %v", err)
	}

	defer listener.Close()
	log.Printf("Listening on %s", serverAddress)

	go readEvents(reader)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn, sockMap)
	}
}

/*
 * =========================================================
 * Attach program to SOCKMAP
 * =========================================================
 */

func attachSockmapProgram(
	program *ebpf.Program,
	sockMap *ebpf.Map,
	attachType ebpf.AttachType,
) error {

	return link.RawAttachProgram(
		link.RawAttachProgramOptions{
			Target:  sockMap.FD(),
			Program: program,
			Attach:  attachType,
		},
	)
}

/*
 * =========================================================
 * TCP connection
 * =========================================================
 */

func handleConnection(
	conn net.Conn,
	sockMap *ebpf.Map,
) {

	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)

	if !ok {
		log.Println(
			"connection is not TCP",
		)

		return
	}

	/*
	 * =====================================================
	 * Get underlying socket FD
	 * =====================================================
	 */

	rawConn, err := tcpConn.SyscallConn()

	if err != nil {

		log.Printf(
			"getting syscall connection: %v",
			err,
		)

		return
	}

	var socketFD int

	err = rawConn.Control(
		func(fd uintptr) {

			socketFD = int(fd)

		},
	)

	if err != nil {

		log.Printf(
			"getting socket FD: %v",
			err,
		)

		return
	}

	/*
	 * =====================================================
	 * Insert socket into SOCKMAP
	 * =====================================================
	 *
	 * IMPORTANT:
	 *
	 * The key is currently always 0.
	 *
	 * This is intentional for our first
	 * single-connection experiment.
	 */

	key := uint32(0)

	if err := sockMap.Update(
		key,
		uint64(socketFD),
		ebpf.UpdateAny,
	); err != nil {

		log.Printf(
			"adding socket to SOCKMAP: %v",
			err,
		)

		return
	}

	log.Printf(
		"TCP socket %d inserted into SOCKMAP",
		socketFD,
	)

	/*
	 * =====================================================
	 * Normal TCP server
	 * =====================================================
	 */

	buffer := make([]byte, 4096)

	n, err := tcpConn.Read(buffer)

	if err != nil {

		log.Printf(
			"TCP read: %v",
			err,
		)

		return
	}

	if n == 0 {
		return
	}

	log.Printf(
		"Application received %d bytes",
		n,
	)

	/*
	 * =====================================================
	 * HTTP response
	 * =====================================================
	 */

	response := []byte(
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 5\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"HELLO",
	)

	_, _ = tcpConn.Write(response)
}

/*
 * =========================================================
 * Ring buffer event reader
 * =========================================================
 */

func readEvents(
	reader *ringbuf.Reader,
) {

	for {

		record, err := reader.Read()

		if err != nil {

			if err == ringbuf.ErrClosed ||
				strings.Contains(
					err.Error(),
					"file already closed",
				) {

				return
			}

			log.Printf(
				"ring buffer read: %v",
				err,
			)

			continue
		}

		var event socketEvent

		if err := binary.Read(
			bytes.NewReader(
				record.RawSample,
			),
			binary.LittleEndian,
			&event,
		); err != nil {

			log.Printf(
				"decoding event: %v",
				err,
			)

			continue
		}

		/*
		 * Prevent malformed length from
		 * causing an invalid slice.
		 */

		length := int(event.DataLen)

		if length > len(event.Data) {
			length = len(event.Data)
		}

		fmt.Printf(
			"\n===== eBPF EVENT =====\n"+
				"timestamp : %d\n"+
				"cookie    : %d\n"+
				"length    : %d\n"+
				"data      : %q\n"+
				"======================\n",
			event.Timestamp,
			event.SocketCookie,
			length,
			event.Data[:length],
		)
	}
}

/*
 * =========================================================
 * Signal handling
 * =========================================================
 */

func closeReaderOnSignal(
	reader *ringbuf.Reader,
) {

	signalChan := make(chan os.Signal, 1)

	signal.Notify(
		signalChan,
		os.Interrupt,
		syscall.SIGTERM,
	)

	go func() {

		<-signalChan

		log.Println(
			"Stopping...",
		)

		reader.Close()
	}()
}
