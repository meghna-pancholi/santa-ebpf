#ifndef __TIMELOOPS_H
#define __TIMELOOPS_H

#define MAX_RB_ENTRIES 8192 /* 8 KB */
#define MAX_MAP_ENTRIES 128
#define TASK_COMM_LEN 16
#define POD_NAME_LEN 128
#define CONTAINER_ID_LENGTH 65
#define MAX_TIMELOOPING_SERVICES 24
#define MAX_NUM_SYSCALLS 341
#define EXEC_STR_LEN 257
#define CGROUP_FILE_FORMAT "/proc/%d/cgroup"
#define BUFFER_SIZE 1024
#define POD_NAME_FILE "/etc/hostname"
#define DEFAULT_NS const_cast<char *>("default")
#define CONFIGMAP_NAME "timeloops-configmap"
#define ORACLE_TIMEOUT 15

char UNKNOWN = 'u';
char NOT_TIMELOOPING = 'n';
char ORACLE = 'o';
char PRODUCTION = 'p';
char DELETING = 'd';

struct event_t
{
	bool syscall;
	bool container_created;
	char container_id[CONTAINER_ID_LENGTH];
	unsigned long syscall_num;
	int policy_val;
	int policy_id;
	uint32_t pid;
};

#endif /* __TIMELOOPS_H */