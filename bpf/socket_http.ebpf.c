//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define INSPECT_WINDOW 2048
#define MAX_WINDOWS 16
#define PATTERN_LEN 7

static const __u8 pattern[PATTERN_LEN] = {
    'P','D','9','w','a','H','A'
};

char LICENSE[] SEC("license") = "GPL";

/*
 * ============================================================
 * Event sent from kernel space -> user space
 * ============================================================
 */

 struct stream_state {
    __u32 pattern_pos;
    __u32 pattern_reported;
    __u64 stream_offset;
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

    __u64 stream_offset;
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
    __type(value, __u32);
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
 *     1. Inspect the bounded stream chunk
 *     2. Put them into a ring-buffer event
 *     3. PASS the data
 *
 * We are NOT blocking anything yet.
 * ============================================================
 */

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

    /*
     * ========================================================
     * Basic event information
     * ========================================================
     */

    event->timestamp = bpf_ktime_get_ns();

    __u64 cookie = bpf_get_socket_cookie(skb);

    event->socket_cookie = cookie;
    event->skb_len = skb_len;

    event->pattern_found = 0;
    event->pattern_offset = 0;

    /*
     * ========================================================
     * Get per-socket matcher state
     * ========================================================
     */
    
    struct stream_state *state;

    state = bpf_map_lookup_elem(
        &stream_states,
        &cookie
    );

    if (!state) {

        struct stream_state initial = {};

        bpf_map_update_elem(
            &stream_states,
            &cookie,
            &initial,
            BPF_ANY
        );

        state = bpf_map_lookup_elem(
            &stream_states,
            &cookie
        );

        if (!state)
            goto submit;
    }
    event->matcher_state_before = state->pattern_pos;
    event->stream_offset = state->stream_offset;
    /*
    * ========================================================
    * Bounded window inspection
    * ========================================================
    */

    event->inspected_len = skb_len;

    if (event->inspected_len > INSPECT_WINDOW * MAX_WINDOWS)
        event->inspected_len = INSPECT_WINDOW * MAX_WINDOWS;

    if (state->pattern_reported)
        goto submit;

    __u64 base_stream_offset = state->stream_offset;
    __u32 stream_advance = skb_len;

    __u32 window_offset = 0;
    __u32 found = 0;

    int w;
    int i;

    bpf_for (w, 0, MAX_WINDOWS) {

        if (window_offset >= skb_len)
            break;

        __u32 remaining = skb_len - window_offset;

        __u32 window_len = remaining;

        if (window_len > INSPECT_WINDOW)
            window_len = INSPECT_WINDOW;


        /*
        * ====================================================
        * Inspect one window
        * ====================================================
        */

        bpf_for (i, 0, INSPECT_WINDOW) {

            if ((__u32)i >= window_len)
                break;

            __u8 c;

            if (bpf_skb_load_bytes(
                skb,
                window_offset + i,
                &c,
                sizeof(c)
            ) < 0)
                break;


            /*
            * Make sure the state-derived
            * array index is bounded.
            */

            if (state->pattern_pos >= PATTERN_LEN)
                state->pattern_pos = 0;


            /*
            * Continue the pattern matcher.
            */

            if (c == pattern[state->pattern_pos]) {

                state->pattern_pos++;

                /*
                * Complete pattern found.
                */

                if (state->pattern_pos == PATTERN_LEN) {

                    event->pattern_found = 1;

                    __u64 current_stream_position =
                        base_stream_offset +
                        window_offset +
                        (__u32)i;

                    event->pattern_offset =
                        current_stream_position -
                        PATTERN_LEN +
                        1;

                    bpf_printk(
                        "SQLi pattern found: offset=%d skb_len=%d",
                        event->pattern_offset,
                        skb_len
                    );

                    state->pattern_pos = 0;
                    state->pattern_reported = 1;
                    found = 1;
                    break;
                }

            } else {

                state->pattern_pos = 0;
            }
        }

        
        /* 
        * Move to the next window.
        */
        if (found)
            break;

        window_offset += window_len;
    }

    state->stream_offset += stream_advance;
    event->matcher_state_after = state->pattern_pos;

    submit:
        bpf_ringbuf_submit(event, 0);
    return SK_PASS;
}