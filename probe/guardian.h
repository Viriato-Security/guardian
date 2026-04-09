/* SPDX-License-Identifier: BUSL-1.1
 * Guardian kernel probe — shared header between eBPF and userspace.
 * Phase 2+ — not compiled in Phase 1.
 *
 * Copyright (c) 2026 Viriato Security Lda.  All rights reserved.
 */

#pragma once

#include <linux/types.h>

/* Maximum lengths for variable-width string fields.
 * Must match agent/generator.py:RawEvent field semantics. */
#define GUARDIAN_PROCESS_LEN   16
#define GUARDIAN_FD_PATH_LEN  256
#define GUARDIAN_NETADDR_LEN   64

/**
 * struct guardian_event - per-syscall telemetry event written to the ring buffer.
 *
 * All fields are filled by the eBPF program and read by the userspace agent.
 * The agent layer (enricher + signer) fills agent_id, model_name, container_id,
 * pod_name, namespace, prev_hash, and this_hash *after* reading from the ring buffer.
 */
struct guardian_event {
    __u64  timestamp_ns;                        /* ktime_get_real_ns() at syscall entry */
    __u32  pid;                                 /* tgid (userspace PID) */
    __u32  uid;                                 /* effective UID */
    __s32  syscall_nr;                          /* syscall number from pt_regs */
    __s32  fd;                                  /* file descriptor (-1 if N/A) */
    __s64  bytes;                               /* bytes transferred (read/write/sendto/recvfrom) */
    __s64  return_val;                          /* syscall return value */
    char   process[GUARDIAN_PROCESS_LEN];       /* task_comm, NUL-terminated */
    char   fd_path[GUARDIAN_FD_PATH_LEN];       /* resolved path for file syscalls */
    char   network_addr[GUARDIAN_NETADDR_LEN];  /* "IP:port" for network syscalls */
};
