package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdp ../xdp.ebpf.c

const interfaceName = "wlp3s0"

const csvFileName = "requests.csv"

/*
 * Must match struct http_event
 * in xdp.ebpf.c.
 */
type httpEvent struct {
	SrcMAC [6]byte
	DstMAC [6]byte

	SrcIP uint32
	DstIP uint32

	SrcPort uint16
	DstPort uint16

	Method  [8]byte
	URL     [64]byte
	Version [16]byte
}

/*
 * Convert C-style null-terminated
 * byte array into Go string.
 */
func cString(data []byte) string {

	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}

	return string(data)
}

/*
 * Format MAC address.
 */
func formatMAC(mac [6]byte) string {
	return net.HardwareAddr(mac[:]).String()
}

/*
 * Format IPv4 address.
 *
 * The IP received from eBPF is
 * in network byte order.
 */
func formatIPv4(ip uint32) string {

	var address [4]byte

	binary.LittleEndian.PutUint32(
		address[:],
		ip,
	)

	return net.IP(address[:]).String()
}

func main() {
	/*
	 * =========================
	 * Remove memory lock limit
	 * =========================
	 */

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	/*
	 * =========================
	 * Find network interface
	 * =========================
	 */

	iface, err := net.InterfaceByName(
		interfaceName,
	)

	if err != nil {
		log.Fatal(err)
	}

	/*
	 * =========================
	 * Load eBPF objects
	 * =========================
	 */

	var objs xdpObjects

	if err := loadXdpObjects(
		&objs,
		nil,
	); err != nil {
		log.Fatal(err)
	}

	defer objs.Close()

	/*
	 * =========================
	 * Attach XDP
	 * =========================
	 */

	l, err := link.AttachXDP(
		link.XDPOptions{
			Program:   objs.XdpProg,
			Interface: iface.Index,
		},
	)

	if err != nil {
		log.Fatal(err)
	}

	defer l.Close()

	log.Printf(
		"XDP Program attached to %s",
		iface.Name,
	)

	/*
	 * =========================
	 * Open ring buffer
	 * =========================
	 */

	reader, err := ringbuf.NewReader(
		objs.Events,
	)

	if err != nil {
		log.Fatal(err)
	}

	defer reader.Close()

	/*
	 * =========================
	 * Open CSV file
	 * =========================
	 */

	file, err := os.OpenFile(
		csvFileName,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	/*
	 * =========================
	 * CSV writer
	 * =========================
	 */

	writer := csv.NewWriter(file)

	defer writer.Flush()

	/*
	 * Write CSV header only
	 * when file is empty.
	 */

	stat, err := file.Stat()

	if err != nil {
		log.Fatal(err)
	}

	if stat.Size() == 0 {

		err := writer.Write([]string{
			"timestamp",
			"src_mac",
			"dst_mac",
			"src_ip",
			"dst_ip",
			"src_port",
			"dst_port",
			"method",
			"url",
			"version",
		})

		if err != nil {
			log.Fatal(err)
		}

		writer.Flush()
	}

	/*
	 * =========================
	 * Signal handling
	 * =========================
	 */

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	/*
	 * Closing the ring buffer
	 * causes reader.Read() to
	 * unblock when Ctrl+C occurs.
	 */

	go func() {
		<-stop
		reader.Close()
	}()

	log.Println(
		"Listening for HTTP requests...",
	)

	/*
	 * =========================
	 * Event loop
	 * =========================
	 */

	for {

		record, err := reader.Read()

		if err != nil {

			if errors.Is(
				err,
				ringbuf.ErrClosed,
			) {
				break
			}

			log.Printf(
				"Ring buffer error: %v",
				err,
			)

			continue
		}

		/*
		 * =========================
		 * Decode event
		 * =========================
		 */

		var event httpEvent

		if err := binary.Read(
			bytes.NewReader(
				record.RawSample,
			),
			binary.LittleEndian,
			&event,
		); err != nil {

			log.Printf(
				"Failed to decode event: %v",
				err,
			)

			continue
		}

		/*
		 * =========================
		 * Convert event
		 * =========================
		 */

		timestamp := time.Now().
			Format(time.RFC3339)

		srcMAC := formatMAC(
			event.SrcMAC,
		)

		dstMAC := formatMAC(
			event.DstMAC,
		)

		srcIP := formatIPv4(
			event.SrcIP,
		)

		dstIP := formatIPv4(
			event.DstIP,
		)

		method := cString(
			event.Method[:],
		)

		url := cString(
			event.URL[:],
		)

		version := cString(
			event.Version[:],
		)

		/*
		 * =========================
		 * Print event
		 * =========================
		 */

		log.Printf(
			"%s:%d -> %s:%d | %s %s %s | %s -> %s",

			srcIP,
			event.SrcPort,

			dstIP,
			event.DstPort,

			method,
			url,
			version,

			srcMAC,
			dstMAC,
		)

		/*
		 * =========================
		 * Write CSV
		 * =========================
		 */

		err = writer.Write([]string{

			timestamp,

			srcMAC,
			dstMAC,

			srcIP,
			dstIP,

			fmt.Sprintf(
				"%d",
				event.SrcPort,
			),

			fmt.Sprintf(
				"%d",
				event.DstPort,
			),

			method,
			url,
			version,
		})

		if err != nil {

			log.Printf(
				"Failed to write CSV: %v",
				err,
			)

			continue
		}

		/*
		 * Flush immediately so
		 * requests.csv is updated.
		 */

		writer.Flush()

		if err := writer.Error(); err != nil {

			log.Printf(
				"CSV writer error: %v",
				err,
			)
		}
	}

	/*
	 * =========================
	 * Shutdown
	 * =========================
	 */

	log.Println(
		"Detaching XDP...",
	)
}
