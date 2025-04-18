#include "vmlinux.h"
#include "timeloops.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// C is row-major
int policy_table[MAX_TIMELOOPING_SERVICES][MAX_NUM_SYSCALLS];

/* BPF hash map to store information about containers running on the node.
 * Container maps to:
 * - 'o' if the container is an oracle
 * - 'p' if the container is a production service
 * - 'n' if it is a non-Timelooping containers
 * - 'u' if it is unknown
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, char *);
	__type(value, char);
} container_types SEC(".maps");

/* BPF hash map to store information about containers running on the node.
 * Container maps to the id of the policy it is associated with
 */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, char *);
	__type(value, int);
} container_ids SEC(".maps");

/* BPF ringbuf map for all events */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_RB_ENTRIES /* 8 * 1024 = 8 KB */);
} rb SEC(".maps");

static inline int is_substring(const char *needle, const int needle_len, const char *s,
															 const int s_len)
{
	// Find the position of the needle in the input string
	int pos = -1;
	for (int i = 0; i <= s_len - needle_len; i++)
	{
		int j;
		for (j = 0; j < needle_len; j++)
		{
			if (s[i + j] != needle[j])
				break;
		}
		if (j == needle_len)
		{
			pos = i + needle_len; // Position after the needle
			return pos;
		}
	}
	return pos;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; // Extract the process ID

	struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid; // Store the PID in the event struct
	event->container_created = true;
	event->syscall = false;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; // Extract the process ID

	struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->container_created = true;
	event->syscall = false;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	// Get container ID from cgroup
	// int jump = 7; // len of docker-
	int jump = 15; // len of cri-containerd-
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	char cgroup_name[CONTAINER_ID_LENGTH] = {};

	const char *cname = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
	if (!cname)
		return 0;

	bpf_core_read_str(cgroup_name, sizeof(cgroup_name), cname + jump);
	if (cgroup_name[0] == '\0')
		return 0;

	// Lookup container type
	char *container_type = bpf_map_lookup_elem(&container_types, cgroup_name);
	if (!container_type || *container_type == NOT_TIMELOOPING)
		return 0; // Container is either not tracked or not timelooping

	// Avoid enforcing policy for runc processes
	char name[TASK_COMM_LEN] = {};
	bpf_get_current_comm(name, sizeof(name));

	const char RUNC_STR[] = "runc";
	if (is_substring(RUNC_STR, 4, name, TASK_COMM_LEN) != -1)
		return 0;

	// If container type is unknown, send SIGKILL (9)
	if (*container_type == UNKNOWN)
	{
		return 0;
	}

	// Get syscall number
	unsigned long syscall_id = ctx->args[1];

	// Lookup policy ID for container
	int *policy_id = bpf_map_lookup_elem(&container_ids, cgroup_name);
	if (!policy_id || *policy_id < 0 || *policy_id >= MAX_TIMELOOPING_SERVICES)
		return 0;

	// Ensure syscall_id is within valid bounds
	if (syscall_id >= MAX_NUM_SYSCALLS)
		return 0;

	// Safely retrieve policy value
	int policy_value = 0;
	if (*policy_id < MAX_TIMELOOPING_SERVICES)
		policy_value = policy_table[*policy_id][syscall_id];

	// If syscall is allowed by policy, exit
	if (policy_value != 0)
		return 0;

	// If container is an ORACLE, update policy and switch back to PRODUCTION
	if (*container_type == ORACLE)
	{
		policy_table[*policy_id][syscall_id] = 1;

		struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
		if (!event)
			return 0;

		event->container_created = false;
		event->syscall = true;
		bpf_probe_read_str(event->container_id, sizeof(event->container_id), cgroup_name);
		event->syscall_num = syscall_id;
		event->policy_val = *policy_id;
		bpf_ringbuf_submit(event, 0);

		return 0;
	}

	// If container is PRODUCTION, report policy violation and send SIGHUP (19)
	if (*container_type == PRODUCTION)
	{
		struct event_t *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
		if (!event)
			return 0;

		event->container_created = false;
		event->syscall = false;
		// bpf_get_current_comm(event->comm, sizeof(event->comm));
		bpf_probe_read_str(event->container_id, sizeof(event->container_id), cgroup_name);
		event->syscall_num = syscall_id;
		event->policy_val = policy_value;
		bpf_ringbuf_submit(event, 0);

		bpf_send_signal(19); // SIGHUP to container violating policy
	}

	return 0;
}
