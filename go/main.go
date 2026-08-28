package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux xdp ../xdp.ebpf.c -- -I/usr/include

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

/*
 * =========================================================
 * HTTP Event
 *
 * Must match struct http_event in xdp.ebpf.c
 * =========================================================
 */

type httpEvent struct {
	SrcMAC [6]byte
	DstMAC [6]byte

	SrcIP uint32
	DstIP uint32

	SrcPort uint16
	DstPort uint16
	PacketLen uint32

	Method  [8]byte
	URL     [64]byte
	Version [16]byte

	HTTPHeader [1024]byte
}

/*
 * =========================================================
 * Parsed HTTP record
 * =========================================================
 */

type HTTPRecord struct {
	Timestamp string

	SrcMAC string
	DstMAC string

	SrcIP string
	DstIP string

	SrcPort uint16
	DstPort uint16
	PacketLen uint32

	Method  string
	URL     string
	Version string

	Headers map[string]string
}

/*
 * =========================================================
 * Global CSV state
 * =========================================================
 */

var records []HTTPRecord

/*
 * HTTP header columns.
 *
 * Example:
 *
 * Host
 * Connection
 * User-Agent
 * Content-Length
 *
 * The order is based on the first time each header
 * is encountered.
 */
var headerColumns []string

var headerSeen = make(map[string]bool)

/*
 * =========================================================
 * C string helper
 *
 * eBPF char arrays are zero-terminated.
 * =========================================================
 */

func cString(data []byte) string {
	if idx := bytes.IndexByte(data, 0); idx >= 0 {
		data = data[:idx]
	}

	return string(data)
}

/*
 * =========================================================
 * MAC formatter
 * =========================================================
 */

func formatMAC(mac [6]byte) string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5],
	)
}

/*
 * =========================================================
 * IPv4 formatter
 *
 * src_ip/dst_ip are kept in network byte order
 * inside the eBPF event.
 * =========================================================
 */

func formatIPv4(ip uint32) string {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	).String()
}

/*
 * =========================================================
 * HTTP Header Parser
 *
 * Input:
 *
 * Host: 10.158.242.211:8000\r\n
 * Connection: keep-alive\r\n
 * User-Agent: Mozilla/5.0\r\n
 * Content-Length: 0\r\n
 *
 * Output:
 *
 * map[string]string{
 *     "Host":           "10.158.242.211:8000",
 *     "Connection":     "keep-alive",
 *     "User-Agent":     "Mozilla/5.0",
 *     "Content-Length": "0",
 * }
 * =========================================================
 */

func parseHTTPHeaders(raw []byte) map[string]string {
	headers := make(map[string]string)

	header := cString(raw)

	/*
	 * HTTP header lines are separated by CRLF.
	 */
	lines := strings.Split(header, "\r\n")

	for _, line := range lines {

		line = strings.TrimSpace(line)

		/*
		 * Empty line.
		 */
		if line == "" {
			continue
		}

		/*
		 * Split only on the FIRST colon.
		 *
		 * This is important because values can contain ':'.
		 *
		 * Example:
		 *
		 * Host: 10.158.242.211:8000
		 *
		 * We want:
		 *
		 * name  = Host
		 * value = 10.158.242.211:8000
		 */
		parts := strings.SplitN(line, ":", 2)

		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if name == "" {
			continue
		}

		headers[name] = value
	}

	return headers
}

/*
 * =========================================================
 * Register HTTP headers
 *
 * Returns true if a new HTTP header was found.
 * =========================================================
 */

func registerHeaders(headers map[string]string) bool {
	newHeader := false

	for name := range headers {

		if !headerSeen[name] {

			headerSeen[name] = true

			headerColumns =
				append(headerColumns, name)

			newHeader = true
		}
	}

	return newHeader
}

/*
 * =========================================================
 * Write CSV
 *
 * Every time a new HTTP header is discovered, the entire
 * CSV is rewritten so that all records have the same columns.
 * =========================================================
 */

func writeCSV(
	filename string,
	records []HTTPRecord,
	headerColumns []string,
) error {

	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)

	/*
	 * =====================================================
	 * Static columns
	 * =====================================================
	 */

	csvHeader := []string{
		"timestamp",
		"src_mac",
		"dst_mac",
		"src_ip",
		"dst_ip",
		"src_port",
		"dst_port",
		"packet_len",
		"method",
		"url",
		"version",
	}

	/*
	 * =====================================================
	 * Dynamic HTTP header columns
	 * =====================================================
	 */

	csvHeader = append(
		csvHeader,
		headerColumns...,
	)

	if err := writer.Write(csvHeader); err != nil {
		return err
	}

	/*
	 * =====================================================
	 * Write every request
	 * =====================================================
	 */

	for _, record := range records {

		row := []string{
			record.Timestamp,
			record.SrcMAC,
			record.DstMAC,
			record.SrcIP,
			record.DstIP,

			strconv.Itoa(
				int(record.SrcPort),
			),

			strconv.Itoa(
				int(record.DstPort),
			),

			strconv.Itoa(
				int(record.PacketLen),
			),

			record.Method,
			record.URL,
			record.Version,
		}

		/*
		 * For every HTTP header column, retrieve
		 * the corresponding value from this request.
		 *
		 * If this request does not contain that header,
		 * the value will be an empty string.
		 */

		for _, name := range headerColumns {

			value := record.Headers[name]

			row = append(
				row,
				value,
			)
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	writer.Flush()

	return writer.Error()
}

/*
 * =========================================================
 * Main
 * =========================================================
 */

func main() {

	/*
	 * =====================================================
	 * Load eBPF objects
	 * =====================================================
	 */

	var objs xdpObjects

	if err := loadXdpObjects(
		&objs,
		&ebpf.CollectionOptions{},
	); err != nil {

		log.Fatalf(
			"loading eBPF objects: %v",
			err,
		)
	}

	defer objs.Close()

	/*
	 * =====================================================
	 * Network interface
	 *
	 * Change this if necessary.
	 *
	 * Example:
	 *
	 * eth0
	 * enp3s0
	 * ens33
	 * =====================================================
	 */

	ifaceName := os.Getenv("XDP_INTERFACE")
	if ifaceName == "" {
		ifaceName = "ens18"
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {

		log.Fatalf(
			"getting interface %s: %v",
			ifaceName,
			err,
		)
	}

	/*
	 * =====================================================
	 * Attach XDP program
	 * =====================================================
	 */

	xdpLink, err := link.AttachXDP(
		link.XDPOptions{
			Program:   objs.XdpProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		},
	)

	if err != nil { 

		log.Fatalf(
			"attaching XDP program: %v",
			err,
		)
	}

	defer xdpLink.Close()

	log.Printf(
		"XDP attached to interface %s",
		ifaceName,
	)

	/*
	 * =====================================================
	 * Ring buffer
	 * =====================================================
	 */

	reader, err :=
		ringbuf.NewReader(objs.Events)

	if err != nil {

		log.Fatalf(
			"creating ring buffer reader: %v",
			err,
		)
	}

	defer reader.Close()

	log.Println(
		"Listening for HTTP requests...",
	)

	/*
	 * =====================================================
	 * Signal handling
	 * =====================================================
	 */

	signalChan := make(
		chan os.Signal,
		1,
	)

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

	/*
	 * =====================================================
	 * Event loop
	 * =====================================================
	 */

	for {

		record, err := reader.Read()

		if err != nil {
			if err == ringbuf.ErrClosed ||
				strings.Contains(err.Error(), "file already closed") {
				break
			}

			log.Printf(
				"reading ring buffer: %v",
				err,
			)

			continue
		}

		/*
		 * =================================================
		 * Decode eBPF event
		 * =================================================
		 */

		var event httpEvent

		err = binary.Read(
			bytes.NewReader(
				record.RawSample,
			),
			binary.LittleEndian,
			&event,
		)

		if err != nil {

			log.Printf(
				"decoding event: %v",
				err,
			)

			continue
		}

		/*
		 * =================================================
		 * Parse HTTP headers in Go
		 * =================================================
		 */

		headers :=
			parseHTTPHeaders(
				event.HTTPHeader[:],
			)

		/*
		 * =================================================
		 * Create HTTP record
		 * =================================================
		 */

		httpRecord := HTTPRecord{

			Timestamp: time.Now().Format(
				time.RFC3339,
			),

			SrcMAC: formatMAC(
				event.SrcMAC,
			),

			DstMAC: formatMAC(
				event.DstMAC,
			),

			SrcIP: formatIPv4(
				event.SrcIP,
			),

			DstIP: formatIPv4(
				event.DstIP,
			),

			SrcPort: event.SrcPort,

			DstPort: event.DstPort,

			PacketLen: event.PacketLen,

			Method: cString(
				event.Method[:],
			),

			URL: cString(
				event.URL[:],
			),

			Version: cString(
				event.Version[:],
			),

			Headers: headers,
		}

		/*
		 * =================================================
		 * Store record
		 * =================================================
		 */

		records =
			append(
				records,
				httpRecord,
			)

		/*
		 * =================================================
		 * Register any new HTTP headers
		 * =================================================
		 */

		registerHeaders(headers)

		/*
		 * =================================================
		 * Rewrite CSV
		 * =================================================
		 */

		err = writeCSV(
			"requests.csv",
			records,
			headerColumns,
		)

		if err != nil {

			log.Printf(
				"writing CSV: %v",
				err,
			)
		}

		/*
		 * =================================================
		 * Console output
		 * =================================================
		 */

		log.Printf(
			"%s %s %s -> %s:%d",
			cString(event.Method[:]),
			cString(event.URL[:]),
			cString(event.Version[:]),
			formatIPv4(event.DstIP),
			event.DstPort,
		)
	}

	log.Println(
		"XDP sniffer stopped.",
	)
}
