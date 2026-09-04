package socket

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux sockethttp ../../bpf/socket_http.ebpf.c -- -I../bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	serverAddress = "192.168.0.2:8000"
)

/*
 * =========================================================
 * Event
 *
 * Must match socket_event in socket_http.bpf.c
 * =========================================================
 */

type socketEvent struct {
	Timestamp          uint64
	SocketCookie       uint64
	SKBLength          uint32
	InspectedLen       uint32
	PatternFound       uint32
	PatternOffset      uint32
	MatcherStateBefore uint32
	MatcherStateAfter  uint32
	StreamOffset       uint32
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
	listener, err := net.Listen("tcp", serverAddress)
	if err != nil {
		log.Fatalf("starting TCP server: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", serverAddress)

	/*
	 * =====================================================
	 * Signal handling
	 * =====================================================
	 */

	signalChan := make(chan os.Signal, 1)

	signal.Notify(
		signalChan,
		os.Interrupt,
		syscall.SIGTERM,
	)

	defer signal.Stop(signalChan)

	/*
	 * When Ctrl+C arrives:
	 *
	 * 1. Close the TCP listener.
	 *    This unblocks listener.Accept().
	 *
	 * 2. Close the ring buffer.
	 *    This unblocks reader.Read().
	 */

	go func() {
		<-signalChan

		log.Println("Stopping...")

		listener.Close()
		reader.Close()
	}()

	/*
	 * =====================================================
	 * Ring-buffer reader
	 * =====================================================
	 */

	go readEvents(reader)

	/*
	 * =====================================================
	 * Accept TCP connections
	 * =====================================================
	 */

	for {
		conn, err := listener.Accept()

		if err != nil {

			/*
			 * listener.Close() was called during shutdown.
			 */
			if errors.Is(err, net.ErrClosed) {
				break
			}

			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn, sockMap)
	}

	log.Println("Socket HTTP monitor stopped.")
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
		log.Println("connection is not TCP")
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
	 * Receive the HTTP request.
	 *
	 * IMPORTANT:
	 *
	 * Do NOT assume one Read() == one HTTP request.
	 * =====================================================
	 */

	buffer := make([]byte, 4096)

	var request []byte

	for {

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

		request = append(
			request,
			buffer[:n]...,
		)

		log.Printf(
			"Application received %d bytes; total=%d",
			n,
			len(request),
		)

		/*
		 * HTTP request headers end with:
		 *
		 * \r\n\r\n
		 */
		if bytes.Contains(
			request,
			[]byte("\r\n\r\n"),
		) {
			break
		}
	}

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

	_, err = tcpConn.Write(response)

	if err != nil {
		log.Printf(
			"writing response: %v",
			err,
		)
	}
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

		fmt.Printf(
			"\n===== eBPF EVENT =====\n"+
				"timestamp      : %d\n"+
				"cookie         : %d\n"+
				"skb_len        : %d\n"+
				"inspected_len  : %d\n"+
				"pattern_found  : %d\n"+
				"pattern_offset : %d\n"+
				"matcher_state_before : %d\n"+
				"matcher_state_after  : %d\n"+
				"stream_offset  : %d\n"+
				"======================\n",
			event.Timestamp,
			event.SocketCookie,
			event.SKBLength,
			event.InspectedLen,
			event.PatternFound,
			event.PatternOffset,
			event.MatcherStateBefore,
			event.MatcherStateAfter,
			event.StreamOffset,
		)
	}
}

/*
 * =========================================================
 * Signal handling
 * =========================================================
 */
