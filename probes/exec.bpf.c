// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("tp/sched/sched_process_exec")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	char buf[16];
	bpf_get_current_comm(&buf, sizeof(buf));
	
	bpf_printk("exec pid=%d comm=%s\n", pid, buf);

	return 0;
}
