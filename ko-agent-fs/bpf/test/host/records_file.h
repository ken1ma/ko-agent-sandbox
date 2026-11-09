/* Reads the guard's records file (ko-agent-fs/policy/include/records.h) for the host build, in a
 * translation unit of its own: policy_host.c compiles policy.bpf.c against the stand-in headers beside
 * it, and this file takes the kernel's type names from the C library instead. */
#ifndef RECORDS_FILE_H
#define RECORDS_FILE_H

#include <stddef.h>

struct records_root {
	unsigned kind;
	const char *path;   /* workspace-relative, empty for the root itself */
};

struct records_file {
	unsigned rule_count;
	unsigned alias_count;
	unsigned root_count;
	const void *rules;      /* rule_count records, contiguous */
	const void *aliases;
	const struct records_root *roots;
};

/* Reads the file into `out`, whose arrays point into memory the reader keeps. On failure, writes
 * the reason into `error` and returns -1. */
int records_file_read(const char *path, struct records_file *out, char *error, size_t error_bytes);

#endif
