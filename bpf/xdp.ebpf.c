//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define HTTP_SERVER_PORT 8000
#define HTTP_HEADER_SIZE 1024

char LICENSE[] SEC("license") = "GPL";

/*
 * Event sent from kernel space
 * to user space.
 */
struct http_event {
    __u8 src_mac[6];
    __u8 dst_mac[6];

    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;
    __u32 packet_len;

    char method[8];
    char url[64];
    char version[16];
    char http_header[HTTP_HEADER_SIZE];
    // char header_line[32];
    // char header_value[16];
    // char header_value[3][16];
};


/*
 * Ring buffer
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;


    /*
     * =========================
     * Ethernet
     * =========================
     */

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;


    /*
     * =========================
     * IPv4
     * =========================
     */

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;

    if ((void *)ip + ip_len > data_end)
        return XDP_PASS;


    /*
     * =========================
     * TCP
     * =========================
     */

    struct tcphdr *tcp = (void *)ip + ip_len;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->doff < 5)
        return XDP_PASS;

    __u32 tcp_len = (__u32)tcp->doff * 4;

    if ((void *)tcp + tcp_len > data_end)
        return XDP_PASS;


    /*
     * =========================
     * HTTP server filter
     * =========================
     */

    if (bpf_ntohs(tcp->dest) != HTTP_SERVER_PORT)
        return XDP_PASS;


    /*
     * =========================
     * Payload
     * =========================
     */

    __u8 *payload = (void *)tcp + tcp_len;

    if (payload >= (__u8 *)data_end)
        return XDP_PASS;


    /*
     * =========================
     * Reserve ring-buffer event
     * =========================
     *
     * IMPORTANT:
     *
     * We allocate the HTTP event directly
     * from the ring buffer instead of
     * creating large arrays on the BPF stack.
     */

    struct http_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return XDP_PASS;


    /*
     * =========================
     * MAC addresses
     * =========================
     */

    __builtin_memcpy(
        event->src_mac,
        eth->h_source,
        6
    );

    __builtin_memcpy(
        event->dst_mac,
        eth->h_dest,
        6
    );


    /*
     * =========================
     * IP addresses
     * =========================
     *
     * Keep network byte order.
     * Go converts it later.
     */

    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;


    /*
     * =========================
     * TCP ports
     * =========================
     *
     * Convert to host byte order.
     */

    event->src_port = bpf_ntohs(tcp->source);
    event->dst_port = bpf_ntohs(tcp->dest);
    event->packet_len = (__u32)((__u8 *)data_end - (__u8 *)data);


    /*
     * =========================
     * HTTP Method
     * =========================
     */

    __u32 method_end = 0;
    bool method_found = false;

    #pragma unroll
    for (int i = 0; i < 7; i++) {

        if ((void *)(payload + i + 1) > data_end)
            break;

        if (payload[i] == ' ') {
            method_end = (__u32)i;
            method_found = true;
            break;
        }

        event->method[i] = payload[i];
    }

    if (!method_found) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }


    /*
     * =========================
     * URL
     * =========================
     */

    __u32 url_start = method_end + 1;
    __u32 url_end = 0;
    bool url_found = false;

    #pragma unroll
    for (int i = 0; i < 63; i++) {

        __u32 offset = url_start + (__u32)i;

        if ((void *)(payload + offset + 1) > data_end)
            break;

        if (payload[offset] == ' ') {
            url_end = offset;
            url_found = true;
            break;
        }

        event->url[i] = payload[offset];
    }

    if (!url_found) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }


    /*
     * =========================
     * HTTP Version
     * =========================
     */

    __u32 version_start = url_end + 1;
    __u32 version_end = 0;
    bool version_found = false;

    #pragma unroll
    for (int i = 0; i < 15; i++) {

        __u32 offset = version_start + (__u32)i;

        if ((void *)(payload + offset + 1) > data_end)
            break;

        if (payload[offset] == '\r') {
            version_end = offset;
            version_found = true;
            break;
        }

        event->version[i] = payload[offset];
    }

    if (!version_found) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }

    // HTTP Header

    /*
    * =========================
    * HTTP Header 1
    * =========================
    */

    // __u32 h1_start = version_end + 2;
    // __u32 h1_end = 0;
    // bool h1_finished = false;

    // int i;

    // bpf_for(i, 0, 32)
    // {
    //     __u32 offset = h1_start + (__u32)i;

    //     if ((void *)(payload + offset + 1) > data_end)
    //         break;

    //     __u8 c = payload[offset];

    //     if (c == '\r') {
    //         h1_end = offset;
    //         h1_finished = true;
    //         break;
    //     }

    //     event->header_line[i] = c;
    // }

    __u32 header_start = version_end + 2;

    int i;

    bpf_for(i, 0, HTTP_HEADER_SIZE)
    {
        __u32 packet_offset =
            (__u32)((__u8 *)payload - (__u8 *)data) +
            header_start + (__u32)i;

        if (bpf_xdp_load_bytes(
                ctx,
                packet_offset,
                &event->http_header[i],
                1
            ) < 0)
            break;

        /*
        * End of HTTP headers:
        *
        * \r\n\r\n
        *
        * Untuk tahap pertama kita cukup
        * menyimpan semuanya sampai packet
        * tidak memiliki data lagi atau buffer
        * mencapai 128 byte.
        */

    }

    /*
    * =========================
    * Submit
    * =========================
    */

    bpf_ringbuf_submit(
        event,
        0
    );

    return XDP_PASS;
}