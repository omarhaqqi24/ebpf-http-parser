package socket

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux sockethttp ../../bpf/socket_http.ebpf.c -- -I../bpf

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/northernside/ktls"
	"golang.org/x/sys/unix"
)

const (
	serverAddress = "10.34.211.178:8000"
	serverCert    = "../server.crt"
	serverKey     = "../server.key"
	socketDataset = "socket_events.csv"
)

type sockMapListener struct {
	net.Listener
	SockMap *ebpf.Map
}

/*
 * =========================================================
 * Userspace representation of socket_event
 * =========================================================
 *
 * This structure must match struct socket_event
 * in socket_http.ebpf.c.
 */

type socketEvent struct {
	Timestamp          uint64
	SocketCookie       uint64
	SKBLength          uint32
	InspectedLen       uint32
	PatternFound       uint32
	EventPadding       [4]byte
	PatternOffset      uint64
	MatcherStateBefore uint32
	MatcherStateAfter  uint32
	StreamOffset       uint64
	BeforeLen          uint32
	AfterLen           uint32
	Before             [64]byte
	After              [64]byte
	PayloadLen         uint32
	Payload            [4096]byte
}

type httpFields struct {
	Method  string
	URL     string
	Version string
	Header  string
}

type tlsFields struct {
	ContentType   string
	Version       string
	RecordLength  int
	HeaderHex     string
	CiphertextHex string
	Found         bool
}

/*
 * =========================================================
 * Main entry point
 * =========================================================
 */

func Run() {
	objs, events, err := setupSocketHTTP()
	if err != nil {
		log.Fatalf("setting up socket HTTP monitor: %v", err)
	}

	defer objs.Close()
	defer events.Close()

	serveTCP(events, objs.SockMap)
}

/*
 * =========================================================
 * eBPF setup
 * =========================================================
 *
 * Current experiment:
 *
 *     SOCKMAP
 *        │
 *        └── SK_SKB stream verdict
 *
 * The parser is attached before the verdict. When kTLS is enabled, kernels
 * with the kTLS/BPF integration skip this parser and run the verdict after
 * TLS RX decryption.
 *
 * The purpose is to establish:
 *
 *     kTLS RX → SK_SKB verdict → userspace event
 */

func setupSocketHTTP() (*sockethttpObjects, *ringbuf.Reader, error) {
	objs := &sockethttpObjects{}

	if err := loadSockethttpObjects(
		objs,
		&ebpf.CollectionOptions{},
	); err != nil {
		return nil, nil, fmt.Errorf(
			"loading eBPF objects: %w",
			err,
		)
	}

	/*
	 * Attach the parser before the verdict. The kernel uses this ordering to
	 * coordinate the BPF stream path with the kTLS receive path.
	 */
	if err := attachSockmapProgram(
		objs.SocketStreamParser,
		objs.SockMap,
		ebpf.AttachSkSKBStreamParser,
	); err != nil {
		objs.Close()

		return nil, nil, fmt.Errorf(
			"attaching stream parser: %w",
			err,
		)
	}

	if err := attachSockmapProgram(
		objs.SocketStreamVerdict,
		objs.SockMap,
		ebpf.AttachSkSKBStreamVerdict,
	); err != nil {
		objs.Close()

		return nil, nil, fmt.Errorf(
			"attaching stream verdict: %w",
			err,
		)
	}

	/*
	 * Create ring-buffer reader.
	 */
	events, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()

		return nil, nil, fmt.Errorf(
			"creating ring buffer reader: %w",
			err,
		)
	}

	log.Println("SK_SKB stream verdict attached")
	log.Println("SK_SKB stream parser attached")

	return objs, events, nil
}

/*
 * =========================================================
 * Attach SK_SKB program to SOCKMAP
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
 * TCP / kTLS server
 * =========================================================
 */

func serveTCP(
	events *ringbuf.Reader,
	sockMap *ebpf.Map,
) {
	tlsConfig, err := createTLSConfig()
	if err != nil {
		log.Fatalf("creating TLS configuration: %v", err)
	}

	/*
	 * Create the underlying TCP listener.
	 */
	tcpListener, err := net.Listen(
		"tcp",
		serverAddress,
	)
	if err != nil {
		log.Fatalf(
			"starting TCP server: %v",
			err,
		)
	}

	mapListener := &sockMapListener{
		Listener: tcpListener,
		SockMap:  sockMap,
	}

	/*
	 * Wrap the TCP listener with the kTLS listener.
	 *
	 * The TLS handshake happens through crypto/tls.
	 * After the handshake, ktls attempts to configure
	 * kernel TLS for the socket.
	 */
	listener := &ktls.Listener{
		TCPListener: mapListener,
		TLSConfig:   tlsConfig,

		OnError: func(err error) {
			log.Printf(
				"kTLS setup failed: %v",
				err,
			)
		},
	}

	defer listener.Close()

	/*
	 * Start ring-buffer reader.
	 */
	go readEvents(events)

	/*
	 * Handle SIGINT / SIGTERM.
	 */
	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	defer signal.Stop(stop)

	go func() {
		<-stop

		log.Println("Stopping server...")

		listener.Close()
		events.Close()
	}()

	log.Printf(
		"HTTPS server listening on %s",
		serverAddress,
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			log.Printf(
				"accept error: %v",
				err,
			)

			continue
		}

		go handleConnection(
			conn,
		)
	}

	log.Println("Socket HTTP monitor stopped.")
}

func (l *sockMapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	socketFD, err := getSocketFD(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("getting accepted socket FD: %w", err)
	}

	key := uint32(socketFD)
	if err := l.SockMap.Update(key, key, ebpf.UpdateAny); err != nil {
		conn.Close()
		return nil, fmt.Errorf("adding socket %d to SOCKHASH before TLS: %w", socketFD, err)
	}

	return &mappedConn{
		Conn:     conn,
		SockMap:  l.SockMap,
		Key:      key,
		SocketFD: socketFD,
	}, nil
}

type mappedConn struct {
	net.Conn
	SockMap  *ebpf.Map
	Key      uint32
	SocketFD int
}

func (c *mappedConn) Close() error {
	if err := c.SockMap.Delete(c.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("removing socket %d from SOCKHASH: %v", c.SocketFD, err)
	}
	return c.Conn.Close()
}

func (c *mappedConn) SyscallConn() (syscall.RawConn, error) {
	rawConn, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("underlying connection does not implement syscall.Conn")
	}

	return rawConn.SyscallConn()
}

/*
 * =========================================================
 * TLS configuration
 * =========================================================
 */

func createTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		serverCert,
		serverKey,
	)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			certificate,
		},

		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,

		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

/*
 * =========================================================
 * Connection handling
 * =========================================================
 *
 * Flow:
 *
 *     accepted connection
 *            │
 *            ▼
 *        socket FD
 *            │
 *            ▼
 *        TCP_ULP check
 *            │
 *            ▼
 *        SOCKMAP insert
 *            │
 *            ▼
 *        read HTTP
 *            │
 *            ▼
 *        send response
 */

func handleConnection(
	conn net.Conn,
) {
	defer conn.Close()

	socketFD, err := getSocketFD(conn)
	if err != nil {
		log.Printf(
			"getting socket FD: %v",
			err,
		)

		return
	}

	log.Printf(
		"accepted connection: socket_fd=%d",
		socketFD,
	)

	/*
	 * -------------------------------------------------------
	 * Check whether kTLS is active.
	 * -------------------------------------------------------
	 */

	enabled, err := kTLSEnabled(socketFD)
	if err != nil {
		log.Printf(
			"socket %d: checking TCP_ULP failed: %v",
			socketFD,
			err,
		)

		return
	}

	if !enabled {
		log.Printf(
			"socket %d: TCP_ULP is not tls; skipping SOCKMAP",
			socketFD,
		)

		return
	}

	log.Printf(
		"socket %d: TCP_ULP=tls",
		socketFD,
	)

	/*
	 * -------------------------------------------------------
	 * Receive HTTP request.
	 * -------------------------------------------------------
	 */

	request, err := readHTTPRequest(conn)
	if err != nil {
		log.Printf(
			"socket %d: reading HTTP request: %v",
			socketFD,
			err,
		)

		return
	}

	log.Printf(
		"socket %d: received HTTP request (%d bytes)",
		socketFD,
		len(request),
	)

	/*
	 * -------------------------------------------------------
	 * Send HTTP response.
	 * -------------------------------------------------------
	 */

	if err := writeHTTPResponse(conn); err != nil {
		log.Printf(
			"socket %d: writing response: %v",
			socketFD,
			err,
		)

		return
	}

	log.Printf(
		"socket %d: response sent",
		socketFD,
	)
}

/*
 * =========================================================
 * Get underlying socket FD
 * =========================================================
 */

func getSocketFD(conn net.Conn) (int, error) {
	rawConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, errors.New(
			"connection does not implement syscall.Conn",
		)
	}

	raw, err := rawConn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var socketFD int

	err = raw.Control(func(fd uintptr) {
		socketFD = int(fd)
	})

	if err != nil {
		return 0, err
	}

	return socketFD, nil
}

/*
 * =========================================================
 * Check kTLS
 * =========================================================
 *
 * This only checks:
 *
 *     TCP_ULP == "tls"
 *
 * It does NOT independently inspect TLS_RX.
 *
 * The ktls library is responsible for installing
 * the TLS_RX configuration after the TLS handshake.
 */

func kTLSEnabled(fd int) (bool, error) {
	ulp, err := unix.GetsockoptString(
		fd,
		unix.IPPROTO_TCP,
		unix.TCP_ULP,
	)
	if err != nil {
		return false, err
	}

	return ulp == "tls", nil
}

/*
 * =========================================================
 * Read HTTP request
 * =========================================================
 */

func readHTTPRequest(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 4096)

	var request []byte
	headerEnd := -1
	contentLength := 0

	for {
		n, err := conn.Read(buffer)

		if n > 0 {
			request = append(request, buffer[:n]...)
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return request, nil
			}
			return nil, err
		}

		if n == 0 {
			return request, nil
		}

		log.Printf(
			"application read: %d bytes (total=%d)",
			n,
			len(request),
		)

		if headerEnd < 0 {
			marker := bytes.Index(request, []byte("\r\n\r\n"))
			if marker >= 0 {
				headerEnd = marker + len("\r\n\r\n")
				contentLength = requestContentLength(request[:marker])
			}
		}

		if headerEnd >= 0 && len(request) >= headerEnd+contentLength {
			return request[:headerEnd+contentLength], nil
		}
	}
}

func requestContentLength(request []byte) int {
	for _, line := range strings.Split(string(request), "\r\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			continue
		}

		length, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || length < 0 {
			return 0
		}
		return length
	}

	return 0
}

/*
 * =========================================================
 * HTTP response
 * =========================================================
 */

func writeHTTPResponse(conn net.Conn) error {
	response := []byte(
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 5\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"HELLO",
	)

	_, err := conn.Write(response)

	return err
}

/*
 * =========================================================
 * Ring-buffer event reader
 * =========================================================
 */

func readEvents(reader *ringbuf.Reader) {
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
			bytes.NewReader(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			log.Printf(
				"decoding event: %v",
				err,
			)

			continue
		}

		payload := event.Payload[:previewLength(event.PayloadLen, len(event.Payload))]
		fields, _ := parseHTTPPayload(payload)
		tls := parseTLSRecord(payload)

		if err := appendSocketEvent(event, fields, tls); err != nil {
			log.Printf("writing socket dataset: %v", err)
		}

		prefix := eventPreview(event.Before[:previewLength(event.BeforeLen, len(event.Before))])

		fmt.Printf(
			"\n===== eBPF EVENT =====\n"+
				"timestamp       : %d\n"+
				"socket_cookie   : %d\n"+
				"skb_len         : %d\n"+
				"inspected_len   : %d\n"+
				"stream_offset   : %d\n"+
				"matcher_state   : %d -> %d\n"+
				"method          : %s\n"+
				"url             : %s\n"+
				"version         : %s\n"+
				"http_header     : %s\n"+
				"tls_header      : %s\n"+
				"tls_type        : %s\n"+
				"tls_version     : %s\n"+
				"tls_record_len  : %d\n"+
				"received_prefix : %s\n"+
				"pattern         : %s\n",
			event.Timestamp,
			event.SocketCookie,
			event.SKBLength,
			event.InspectedLen,
			event.StreamOffset,
			event.MatcherStateBefore,
			event.MatcherStateAfter,
			fields.Method,
			fields.URL,
			fields.Version,
			fields.Header,
			tls.HeaderHex,
			tls.ContentType,
			tls.Version,
			tls.RecordLength,
			prefix,
			patternResult(event),
		)

		if !isPrintable(event.Before[:previewLength(event.BeforeLen, len(event.Before))]) {
			fmt.Printf("received_prefix_hex: %x\n", event.Before[:previewLength(event.BeforeLen, len(event.Before))])
		}

		fmt.Println("========================")
	}
}

func appendSocketEvent(event socketEvent, fields httpFields, tls tlsFields) error {
	filename := filepath.Clean(filepath.Join(filepath.Dir(os.Args[0]), "..", socketDataset))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	writer := csv.NewWriter(file)
	if info.Size() == 0 {
		if err := writer.Write([]string{
			"capture_source",
			"detected",
			"dataset_timestamp",
			"timestamp",
			"socket_cookie",
			"skb_len",
			"inspected_len",
			"stream_offset",
			"method",
			"url",
			"version",
			"http_header",
			"payload_len",
			"payload",
			"payload_hex",
			"tls_content_type",
			"tls_version",
			"tls_record_length",
			"tls_ciphertext_hex",
			"received_prefix",
			"received_suffix",
			"pattern_found",
			"pattern_offset",
		}); err != nil {
			return err
		}
	}

	before := event.Before[:previewLength(event.BeforeLen, len(event.Before))]
	after := event.After[:previewLength(event.AfterLen, len(event.After))]
	payload := event.Payload[:previewLength(event.PayloadLen, len(event.Payload))]

	if err := writer.Write([]string{
		"ebpf_sk_skb_stream_verdict",
		strconv.FormatBool(event.PatternFound != 0),
		time.Now().UTC().Format(time.RFC3339Nano),
		strconv.FormatUint(event.Timestamp, 10),
		strconv.FormatUint(event.SocketCookie, 10),
		strconv.FormatUint(uint64(event.SKBLength), 10),
		strconv.FormatUint(uint64(event.InspectedLen), 10),
		strconv.FormatUint(event.StreamOffset, 10),
		fields.Method,
		fields.URL,
		fields.Version,
		eventPreview([]byte(fields.Header)),
		strconv.FormatUint(uint64(event.PayloadLen), 10),
		eventPreview(payload),
		fmt.Sprintf("%x", payload),
		tls.ContentType,
		tls.Version,
		strconv.Itoa(tls.RecordLength),
		tls.CiphertextHex,
		eventPreview(before),
		eventPreview(after),
		strconv.FormatUint(uint64(event.PatternFound), 10),
		strconv.FormatUint(event.PatternOffset, 10),
	}); err != nil {
		return err
	}

	writer.Flush()
	return writer.Error()
}

func parseTLSRecord(payload []byte) tlsFields {
	if len(payload) < 5 || payload[1] != 3 || payload[2] > 4 {
		return tlsFields{}
	}

	contentType := map[byte]string{
		20: "change_cipher_spec",
		21: "alert",
		22: "handshake",
		23: "application_data",
	}
	name, ok := contentType[payload[0]]
	if !ok {
		return tlsFields{}
	}

	version := map[byte]string{
		1: "TLS 1.0",
		2: "TLS 1.1",
		3: "TLS 1.2",
		4: "TLS 1.3",
	}[payload[2]]

	recordLength := int(binary.BigEndian.Uint16(payload[3:5]))
	end := 5 + recordLength
	if end > len(payload) {
		end = len(payload)
	}

	return tlsFields{
		ContentType:   name,
		Version:       version,
		RecordLength:  recordLength,
		HeaderHex:     fmt.Sprintf("%x", payload[:5]),
		CiphertextHex: fmt.Sprintf("%x", payload[5:end]),
		Found:         true,
	}
}

func parseHTTPPayload(payload []byte) (httpFields, bool) {
	payload = bytes.TrimLeft(payload, "\x00")
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return httpFields{}, false
	}

	lineEnd := bytes.Index(payload, []byte("\r\n"))
	if lineEnd < 0 {
		return httpFields{}, false
	}

	parts := strings.SplitN(string(payload[:lineEnd]), " ", 3)
	if len(parts) != 3 || !isHTTPMethod(parts[0]) || !strings.HasPrefix(parts[2], "HTTP/") {
		return httpFields{}, false
	}

	return httpFields{
		Method:  parts[0],
		URL:     parts[1],
		Version: parts[2],
		Header:  string(payload[lineEnd+2 : headerEnd+2]),
	}, true
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func previewLength(length uint32, capacity int) int {
	if int(length) > capacity {
		return capacity
	}
	return int(length)
}

func eventPreview(data []byte) string {
	return strconv.QuoteToASCII(string(data))
}

func isPrintable(data []byte) bool {
	for _, value := range data {
		if value < 0x20 || value > 0x7e {
			return false
		}
	}
	return true
}

func patternResult(event socketEvent) string {
	if event.PatternFound == 0 {
		return "not found"
	}
	return fmt.Sprintf("found at stream offset %d", event.PatternOffset)
}
