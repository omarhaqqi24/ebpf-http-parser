//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_DATA_SIZE 1024
#define MAX_INSPECT_SIZE 1024
#define PATTERN "UNION SELECT"
#define PATTERN_LEN (sizeof(PATTERN) - 1)

char LICENSE[] SEC("license") = "GPL";

/*
 * ============================================================
 * Event sent from kernel space -> user space
 * ============================================================
 */

 struct stream_state {
    __u32 pattern_pos;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);

    __type(key, __u64);
    __type(value, struct stream_state);
} stream_states SEC(".maps");

struct socket_event {
    __u64 timestamp;
    __u64 socket_cookie;

    __u32 skb_len;
    __u32 inspected_len;

    __u32 pattern_found;
    __u32 pattern_offset;

    __u32 matcher_state_before;
    __u32 matcher_state_after;
};


/*
 * ============================================================
 * Ring buffer
 * ============================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


/*
 * ============================================================
 * SOCKMAP
 * ============================================================
 *
 * Userspace will insert TCP socket FDs here.
 *
 * The socket inherits the parser/verdict programs
 * attached to this map.
 * ============================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);

    __uint(max_entries, 64);

    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");


/*
 * ============================================================
 * STREAM PARSER
 * ============================================================
 *
 * For now we deliberately make this a no-op parser.
 *
 * Returning skb->len means:
 *
 *     "Treat the currently presented stream data
 *      as one unit for the verdict program."
 *
 * This is NOT our final HTTP parser.
 *
 * The purpose is to first discover what data reaches
 * the socket-level eBPF path.
 * ============================================================
 */
SEC("sk_skb/stream_parser")
int socket_stream_parser(struct __sk_buff *skb)
{
    return skb->len;
}


/*
 * ============================================================
 * STREAM VERDICT
 * ============================================================
 *
 * This is where we inspect the data.
 *
 * For now:
 *
 *     1. Read up to MAX_DATA_SIZE bytes
 *     2. Put them into a ring-buffer event
 *     3. PASS the data
 *
 * We are NOT blocking anything yet.
 * ============================================================
 */

static const char pattern[] = "UNION SELECT";

SEC("sk_skb/stream_verdict")
int socket_stream_verdict(struct __sk_buff *skb)
{
    struct socket_event *event;

    __u32 skb_len = skb->len;

    if (skb_len == 0)
        return SK_PASS;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return SK_PASS;

    event->timestamp = bpf_ktime_get_ns();
    event->socket_cookie = bpf_get_socket_cookie(skb);
    event->skb_len = skb_len;

    event->pattern_found = 0;
    event->pattern_offset = 0;

    __u32 search_limit = skb_len;

    if (search_limit > MAX_INSPECT_SIZE)
        search_limit = MAX_INSPECT_SIZE;

    if (search_limit < PATTERN_LEN)
        goto submit;

    event->inspected_len = search_limit;
    __u32 max_offset = search_limit - PATTERN_LEN;

    int i;

    bpf_for(i, 0, MAX_INSPECT_SIZE) {

        if ((__u32)i > max_offset)
            break;

        char buf[PATTERN_LEN];

        if (bpf_skb_load_bytes(
            skb,
            i,
            buf,
            PATTERN_LEN
        ) < 0)
            break;

        bool match = true;

        int j;

        bpf_for(j, 0, PATTERN_LEN) {

            if (buf[j] != pattern[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            event->pattern_found = 1;
            event->pattern_offset = i;
            bpf_printk(
                "SQLi pattern found: offset=%d skb_len=%d",
                i,
                skb_len
            );
            break;
        }
    }

submit:

    bpf_ringbuf_submit(event, 0);

    return SK_PASS;
}