#ifndef EVENT_H
#define EVENT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

struct event {
	int pid;
	int ppid;
	unsigned long long cgroup_id;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif
