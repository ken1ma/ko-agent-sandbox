/* libbpf's CO-RE reads for the host build: a plain field read, which, as the kernel's probe read
 * does, yields 0 through a null pointer instead of faulting. */
#ifndef HOST_BPF_CORE_READ_H
#define HOST_BPF_CORE_READ_H

#include <stddef.h>

/* `__attribute__((preserve_access_index))` becomes the empty attribute list. */
#define preserve_access_index

#define core_read1_(src, a)                      \
	({                                       \
		typeof(src) core_s_ = (src);     \
		typeof(core_s_->a) core_v_ = 0;  \
		if (core_s_)                     \
			core_v_ = core_s_->a;    \
		core_v_;                         \
	})
#define core_read2_(src, a, b) core_read1_(core_read1_(src, a), b)
#define core_read3_(src, a, b, c) core_read1_(core_read2_(src, a, b), c)
#define core_pick_(a1_, a2_, a3_, name, ...) name
#define BPF_CORE_READ(src, ...) core_pick_(__VA_ARGS__, core_read3_, core_read2_, core_read1_)(src, __VA_ARGS__)

/* The flavors' fields (`mnt_namespace___anon`, `mnt_namespace___seq`) exist on neither host, so
 * file_receive takes its last branch; the corpus does not drive it. */
#define bpf_core_field_exists(field) 0
#define bpf_core_field_offset(type, field) offsetof(type, field)

#endif
