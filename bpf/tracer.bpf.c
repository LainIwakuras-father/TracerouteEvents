#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


const char kprobe_sys_msg[12] = "sys_execve";
const char tp_sys_msg[12] = "sys_openat";
const char kprobe_tcp_msg[12] = "tcp_connect";
struct event {
	__u32 pid;
	__u64 cgroup_id;
    char  comm[16];
    char message[12];
};




// определение ringbuff
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
// определения HASH MAP




struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u8);
} hash_map_cgroups SEC(".maps");

// секция события
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *hit = bpf_map_lookup_elem(&hash_map_cgroups, &cgroup_id);
    if (!hit) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    e->pid = pid;
    e->cgroup_id = cgroup_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // __builtin_memcpy(&e->message,&kprobe_sys_msg, sizeof(kprobe_sys_msg));
    bpf_probe_read_kernel(e->message, sizeof(e->message), kprobe_sys_msg);

    /* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *hit = bpf_map_lookup_elem(&hash_map_cgroups, &cgroup_id);
    if (!hit) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    e->pid = pid;
    e->cgroup_id = cgroup_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // __builtin_memcpy(&e->message,&kprobe_sys_msg, sizeof(kprobe_sys_msg));
    bpf_probe_read_kernel(e->message, sizeof(e->message), tp_sys_msg);

    /* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx)
{
    struct event *e;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *hit = bpf_map_lookup_elem(&hash_map_cgroups, &cgroup_id);
    if (!hit) return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    e->pid = pid;
    e->cgroup_id = cgroup_id;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // __builtin_memcpy(&e->message,&kprobe_sys_msg, sizeof(kprobe_sys_msg));
    bpf_probe_read_kernel(e->message, sizeof(e->message), kprobe_tcp_msg);

    /* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";