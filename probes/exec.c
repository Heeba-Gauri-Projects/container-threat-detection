// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "event.h"
#include "exec.skel.h"	

static volatile sig_atomic_t stop;

static void sig_handler(int sig)
{
	stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	printf("pid=%d ppid=%d comm=%s filename=%s cgroup_id=%llu\n",
	       e->pid, e->ppid, e->comm, e->filename, e->cgroup_id);
	return 0;
}

int main(void)
{
	struct exec_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = exec_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF skeleton\n");
		return 1;
	}

	err = exec_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	while (!stop) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "poll error: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	exec_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
