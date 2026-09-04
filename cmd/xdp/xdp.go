package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux xdp ../../bpf/xdp.ebpf.c -- -I../bpf

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"fmt"
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

	SrcPort   uint16
	DstPort   uint16
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

	SrcPort   uint16
	DstPort   uint16
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

var csvHeaderWritten bool

const defaultInterface = "ens18"

var requestsCSV = filepath.Clean(filepath.Join(filepath.Dir(os.Args[0]), "..", "requests.csv"))

var csvStaticColumns = []string{
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
			// Appending cannot safely add a new CSV column after the
			// header has been written, so keep the established schema.
			if csvHeaderWritten {
				continue
			}

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
 * Appends one request at a time. The header is written only when
 * requests.csv is created for the first time.
 * =========================================================
 */

func appendCSV(
	filename string,
	record HTTPRecord,
	headerColumns []string,
) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	defer file.Close()

	writer := csv.NewWriter(file)

	if !csvHeaderWritten {
		if err := writer.Write(buildCSVHeader(headerColumns)); err != nil {
			return err
		}
		csvHeaderWritten = true
	}

	if err := writer.Write(buildCSVRow(record, headerColumns)); err != nil {
		return err
	}

	writer.Flush()

	return writer.Error()
}

// loadCSVHeader restores the column order from an existing CSV so appended
// rows remain aligned with the header written by an earlier program run.
func loadCSVHeader(filename string) error {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	header, err := csv.NewReader(file).Read()
	if err != nil {
		return fmt.Errorf("reading CSV header: %w", err)
	}
	if len(header) < len(csvStaticColumns) {
		return fmt.Errorf("CSV header has %d columns, expected at least %d", len(header), len(csvStaticColumns))
	}

	for index, name := range csvStaticColumns {
		if strings.TrimSpace(header[index]) != name {
			return fmt.Errorf("CSV column %d is %q, expected %q", index+1, header[index], name)
		}
	}

	for _, name := range header[len(csvStaticColumns):] {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		headerSeen[name] = true
		headerColumns = append(headerColumns, name)
	}

	csvHeaderWritten = true
	return nil
}

func buildCSVHeader(headerColumns []string) []string {
	header := make([]string, 0, len(csvStaticColumns)+len(headerColumns))
	header = append(header, csvStaticColumns...)
	return append(header, headerColumns...)
}

func buildCSVRow(record HTTPRecord, headerColumns []string) []string {
	row := []string{
		record.Timestamp,
		record.SrcMAC,
		record.DstMAC,
		record.SrcIP,
		record.DstIP,
		strconv.Itoa(int(record.SrcPort)),
		strconv.Itoa(int(record.DstPort)),
		strconv.Itoa(int(record.PacketLen)),
		record.Method,
		record.URL,
		record.Version,
	}

	for _, name := range headerColumns {
		row = append(row, record.Headers[name])
	}

	return row
}

/*
 * =========================================================
 * Main
 * =========================================================
 */

// Run attaches the XDP program and writes captured HTTP requests to CSV.
func Run() {
	if err := loadCSVHeader(requestsCSV); err != nil {
		log.Fatalf("loading CSV header: %v", err)
	}

	var objs xdpObjects
	if err := loadXdpObjects(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}

	defer objs.Close()

	ifaceName := configuredInterface()
	xdpLink, err := attachXDPProgram(objs.XdpProg, ifaceName)
	if err != nil {
		log.Fatalf("attaching XDP program: %v", err)
	}

	defer xdpLink.Close()
	log.Printf("XDP attached to interface %s", ifaceName)

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ring buffer reader: %v", err)
	}

	defer reader.Close()
	log.Println("Listening for HTTP requests...")
	closeReaderOnSignal(reader)
	runEventLoop(reader)
	log.Println("XDP sniffer stopped.")
}

func configuredInterface() string {
	if ifaceName := os.Getenv("XDP_INTERFACE"); ifaceName != "" {
		return ifaceName
	}

	return defaultInterface
}

func attachXDPProgram(program *ebpf.Program, ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	return link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
}

func closeReaderOnSignal(reader *ringbuf.Reader) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		log.Println("Stopping...")
		reader.Close()
	}()
}

func runEventLoop(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed || strings.Contains(err.Error(), "file already closed") {
				return
			}

			log.Printf("reading ring buffer: %v", err)
			continue
		}

		event, err := decodeHTTPEvent(record.RawSample)
		if err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		handleHTTPEvent(event)
	}
}

func decodeHTTPEvent(rawSample []byte) (httpEvent, error) {
	var event httpEvent
	err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event)
	return event, err
}

func handleHTTPEvent(event httpEvent) {
	record := newHTTPRecord(event)
	registerHeaders(record.Headers)

	if err := appendCSV(requestsCSV, record, headerColumns); err != nil {
		log.Printf("writing CSV: %v", err)
	}

	logHTTPEvent(record)
}

func newHTTPRecord(event httpEvent) HTTPRecord {
	return HTTPRecord{
		Timestamp: time.Now().Format(time.RFC3339),
		SrcMAC:    formatMAC(event.SrcMAC),
		DstMAC:    formatMAC(event.DstMAC),
		SrcIP:     formatIPv4(event.SrcIP),
		DstIP:     formatIPv4(event.DstIP),
		SrcPort:   event.SrcPort,
		DstPort:   event.DstPort,
		PacketLen: event.PacketLen,
		Method:    cString(event.Method[:]),
		URL:       cString(event.URL[:]),
		Version:   cString(event.Version[:]),
		Headers:   parseHTTPHeaders(event.HTTPHeader[:]),
	}
}

func logHTTPEvent(record HTTPRecord) {
	log.Printf("%s %s %s -> %s:%d", record.Method, record.URL, record.Version, record.DstIP, record.DstPort)
}
