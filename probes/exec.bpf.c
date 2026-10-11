// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_tp(struct trace_event_raw_sched_process_exec *ctx)
{

	struct task_struct *task;
	struct event *e;
	unsigned int off;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));	

	off = ctx->__data_loc_filename & 0xFFFF;
	if (bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
				      (void *)ctx + off) < 0)
		e->filename[0] = '\0';

	bpf_ringbuf_submit(e, 0);

	return 0;
}
