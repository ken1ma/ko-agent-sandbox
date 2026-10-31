/* The guard's records file (fuse/ko-agent-fs/include/records.h), read for the host build. Its own
 * translation unit, since policy.bpf.c defines the record structs itself and the header cannot
 * join it. */
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
	size_t rule_bytes;      /* sizeof one rule_line record, for the reader to compare with its own */
	size_t alias_bytes;
	const void *rules;      /* rule_count records, contiguous */
	const void *aliases;
	const struct records_root *roots;
};

/* Reads the file into `out`, whose arrays point into memory the reader keeps; on failure writes
 * the reason into `error` and returns -1. */
int records_file_read(const char *path, struct records_file *out, char *error, size_t error_bytes);

#endif
