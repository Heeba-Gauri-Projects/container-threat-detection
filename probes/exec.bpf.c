// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("tp/sched/sched_process_exec")
int handle_tp(struct trace_event_raw_sched_process_exec *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	char buf[16];
	char filename[128];
	unsigned int off;
	bpf_get_current_comm(&buf, sizeof(buf));

	off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&filename, sizeof(filename), (void *)ctx + off);
	
	bpf_printk("exec pid=%d comm=%s filename=%s\n", pid, buf,filename);

	return 0;
}
