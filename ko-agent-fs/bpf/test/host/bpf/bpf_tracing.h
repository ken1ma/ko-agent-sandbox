/* libbpf's BPF_PROG for the host build: a hook is a plain function of its arguments. */
#ifndef HOST_BPF_TRACING_H
#define HOST_BPF_TRACING_H

#define BPF_PROG(name, args...) name(args)

#endif
