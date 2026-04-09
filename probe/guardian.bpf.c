// SPDX-License-Identifier: BUSL-1.1
// Guardian eBPF probe — Phase 2 stub.
// Copyright (c) 2026 Viriato Security Lda.  All rights reserved.
//
// This file shows the correct libbpf + BTF structure and the implemented
// tracepoints for read, openat, and execve.
// Full coverage of write/connect/sendto/recvfrom/clone/socket is Phase 2 TODO.
//
// Build requirements:
//   Linux 5.8+   (ring buffer + BTF support)
//   clang 14+    with BPF target support
//   libbpf 1.x
//
// Build command (Phase 2):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I./probe \
//     -c probe/guardian.bpf.c -o probe/guardian.bpf.o

#include "vmlinux.h"          // BTF-derived kernel type definitions (auto-generated)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "guardian.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/**
 * events — ring buffer shared between the eBPF program and userspace.
 * 256 KB capacity; the agent reads and drains it in a tight loop.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/**
 * watched_pids — hash map populated by userspace with PIDs to monitor.
 * Key: pid (u32), Value: 1 (u8, presence sentinel).
 * The eBPF program drops events for PIDs not in this map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline int is_watched(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

static __always_inline struct guardian_event *reserve_event(void) {
    return bpf_ringbuf_reserve(&events, sizeof(struct guardian_event), 0);
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_read
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    if (!is_watched())
        return 0;

    struct guardian_event *e = reserve_event();
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_real_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr   = 0;  // __NR_read
    e->fd           = (int)ctx->args[0];
    e->bytes        = (long)ctx->args[2];
    e->return_val   = 0;  // filled on sys_exit
    bpf_get_current_comm(e->process, sizeof(e->process));
    // fd_path resolution requires a separate sys_exit probe — Phase 2 TODO

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!is_watched())
        return 0;

    struct guardian_event *e = reserve_event();
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_real_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr   = 257;  // __NR_openat
    e->fd           = -1;
    e->bytes        = 0;
    e->return_val   = 0;
    bpf_get_current_comm(e->process, sizeof(e->process));

    // Read the filename from userspace pointer (ctx->args[1])
    const char *filename = (const char *)(unsigned long)ctx->args[1];
    bpf_probe_read_user_str(e->fd_path, sizeof(e->fd_path), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_execve
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    if (!is_watched())
        return 0;

    struct guardian_event *e = reserve_event();
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_real_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->syscall_nr   = 59;  // __NR_execve
    e->fd           = -1;
    e->bytes        = 0;
    e->return_val   = 0;
    bpf_get_current_comm(e->process, sizeof(e->process));

    const char *filename = (const char *)(unsigned long)ctx->args[0];
    bpf_probe_read_user_str(e->fd_path, sizeof(e->fd_path), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Phase 2 TODOs — tracepoints for remaining syscalls
// ---------------------------------------------------------------------------
// SEC("tracepoint/syscalls/sys_enter_write")    int handle_write(...)
// SEC("tracepoint/syscalls/sys_enter_connect")  int handle_connect(...)
// SEC("tracepoint/syscalls/sys_enter_sendto")   int handle_sendto(...)
// SEC("tracepoint/syscalls/sys_enter_recvfrom") int handle_recvfrom(...)
// SEC("tracepoint/syscalls/sys_enter_clone")    int handle_clone(...)
// SEC("tracepoint/syscalls/sys_enter_socket")   int handle_socket(...)
