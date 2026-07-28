#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    bool IS_DEBUG = false;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ETHERNET HEADER CHECK

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        if (IS_DEBUG) bpf_printk("[PASS] Ethernet header larger than expected");
        return XDP_PASS;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        if (IS_DEBUG) bpf_printk("[PASS] Packet is not IPv4 packet");
        return XDP_PASS;
    }

    // IP HEADER CHECK

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end) {
        if (IS_DEBUG) bpf_printk("[PASS] IP header larger than expected");
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        if (IS_DEBUG) bpf_printk("[PASS] Packet is not TCP packet");
        return XDP_PASS;
    }

    // TCP HEADER CHECK

    __u32 ip_hdr_len = ip->ihl * 4;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;

    if ((void *)(tcp+1) > data_end)
    {
        if (IS_DEBUG) bpf_printk("[PASS] TCP header larger than expected");
        return XDP_PASS;
    }

    // TCP PAYLOAD CHECK (HTTP REQUEST)

    __u32 tcp_hdr_len = tcp->doff * 4;

    char *tcp_payload = (void *)tcp + tcp_hdr_len;

    if ((void *)(tcp_payload + 4) > data_end)
    {
        if (IS_DEBUG) bpf_printk("[PASS] Packet is less than 4 bytes");
        return XDP_PASS;
    }
    
    // VERIFY HTTP PACKET

    // Port check

    __u32 HTTP_SERVER_PORT = 8000;

    if (bpf_ntohs(tcp->dest) != 8000)
    {
        if (IS_DEBUG) bpf_printk("[PASS] Packet destination port is not %d", HTTP_SERVER_PORT);
        return XDP_PASS;
    }
    
    // HTTP PARSING

    __u8 *ip_dst = (__u8 *)&ip->daddr;
    __u8 *ip_src = (__u8 *)&ip->saddr;

    char http_method[8] = {};
    int method_start = 0;
    int method_end = -1;
    
    for (int i = 0; i < sizeof(http_method) - 1; i++)
    {
        if ((void *)(tcp_payload + i + 1) > data_end) break;
        if (tcp_payload[i] == ' ') {
            method_end = i;
            break;
        }

        http_method[i] = tcp_payload[i];
    }

    char http_url[128] = {};
    int url_start = method_end+1;
    int url_end = -1;

    for (int i = 0; i < sizeof(http_url) - 1; i++)
    {
        if ((void *)(tcp_payload + url_start + i + 1) > data_end)
            break;
        if (tcp_payload[url_start + i] == ' ')
        {
            url_end = url_start + i;
            break;
        }
        
        http_url[i] = tcp_payload[url_start + i];
    }

    char http_version[16] = {};
    int version_start = url_end + 1;
    int version_end = -1;

    for (int i = 0; i < sizeof(http_version) - 1; i++)
    {
        if ((void *)(tcp_payload + version_start + i + 1) > data_end)
            break;
        
        if (tcp_payload[version_start+i] == '\r')
        {
            version_end = version_start + i;
            break;
        }

        http_version[i] = tcp_payload[version_start + i];
    }    
    
    bpf_printk("==================================");
    bpf_printk("[RECEIVED] IPv4 TCP Packets");
    bpf_printk("SRC     = %d.%d.%d.%d:%d", ip_src[0], ip_src[1], ip_src[2], ip_src[3], bpf_ntohs(tcp->source));
    bpf_printk("DST     = %d.%d.%d.%d:%d", ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3], bpf_ntohs(tcp->dest));
    bpf_printk("PORT    = TCP");
    bpf_printk("METHOD  = %s", http_method);
    bpf_printk("URL     = %s", http_url);
    bpf_printk("VERSION = %s", http_version);

    bpf_printk("==================================");

    return XDP_PASS;
}

char copy_until(int start, int *end, char stop, int size)
{
    char data[size] = {};
    for (int i = 0; i < sizeof(data) - 1; i++)
    {
        /* code */
    }
    
}