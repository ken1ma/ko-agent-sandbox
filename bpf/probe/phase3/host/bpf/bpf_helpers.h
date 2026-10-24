/* libbpf's bpf_helpers.h as policy.bpf.c uses it, for the host build (../policy_host.c, which
 * defines the helpers). */
#ifndef HOST_BPF_HELPERS_H
#define HOST_BPF_HELPERS_H

#define SEC(name)
#define __uint(name, val) int name
#define __type(name, val) val *name
#undef __always_inline  /* glibc's <sys/cdefs.h> defines one */
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define barrier_var(var) asm volatile("" : "+r"(var))

/* As libbpf's: `i` takes each value from `start` to `end` - 1 and keeps the last one it took, so a
 * loop that runs out leaves `i` at `end` - 1, not `end`. */
#define bpf_for(i, start, end) \
	for (int bpf_for_k_ = (int)(start); bpf_for_k_ < (int)(end) && (((i) = bpf_for_k_), 1); bpf_for_k_++)

void *bpf_map_lookup_elem(const void *map, const void *key);
long bpf_probe_read_kernel(void *dst, __u32 size, const void *src);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *src);
long bpf_strncmp(const char *s1, __u32 s1_sz, const char *s2);
__u64 bpf_ktime_get_ns(void);
struct task_struct *bpf_get_current_task_btf(void);
long bpf_get_current_comm(void *buf, __u32 size);

#endif
