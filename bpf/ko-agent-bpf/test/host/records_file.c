#include "records_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* records.h takes the kernel's type names; <linux/types.h> has them on Linux alone. */
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef int32_t __s32;

/* fuse/ko-agent-fs/include, on the include path: the builder names it, since the self-test image
 * lays the sources out apart from the crate (container/ko-agent-self-test/Containerfile). */
#include "records.h"

static struct records_root roots[ROOTS];

int records_file_read(const char *path, struct records_file *out, char *error, size_t error_bytes)
{
	struct records_header header;
	FILE *file = fopen(path, "rb");
	size_t rule_bytes, alias_bytes;
	void *rules, *aliases;
	struct guarded_path *guarded;

	if (!file) {
		snprintf(error, error_bytes, "%s: %s", path, strerror(errno));
		return -1;
	}
	if (fread(&header, sizeof(header), 1, file) != 1 || memcmp(header.magic, RECORDS_MAGIC, 8) != 0) {
		snprintf(error, error_bytes, "%s: not a records file", path);
		return -1;
	}
	if (header.layout != RECORDS_LAYOUT) {
		snprintf(error, error_bytes, "%s: layout %08x, this build reads %08x", path, header.layout,
			 RECORDS_LAYOUT);
		return -1;
	}
	if (header.rule_count > RULE_LINES || header.alias_count > ALIASES || header.root_count > ROOTS) {
		snprintf(error, error_bytes, "%s: counts %u/%u/%u exceed the policy's bounds", path,
			 header.rule_count, header.alias_count, header.root_count);
		return -1;
	}
	rule_bytes = (size_t)header.rule_count * sizeof(struct rule_line);
	alias_bytes = (size_t)header.alias_count * sizeof(struct alias_context);
	rules = malloc(rule_bytes + 1);
	aliases = malloc(alias_bytes + 1);
	guarded = calloc(header.root_count + 1, sizeof(*guarded));
	if (!rules || !aliases || !guarded) {
		snprintf(error, error_bytes, "out of memory");
		return -1;
	}
	if (fread(rules, 1, rule_bytes, file) != rule_bytes || fread(aliases, 1, alias_bytes, file) != alias_bytes ||
	    fread(guarded, sizeof(*guarded), header.root_count, file) != header.root_count || fgetc(file) != EOF) {
		snprintf(error, error_bytes, "%s: its size does not match its counts", path);
		return -1;
	}
	fclose(file);
	for (unsigned i = 0; i < header.root_count; i++) {
		if (guarded[i].len >= PATH_BYTES || guarded[i].path[guarded[i].len] != 0) {
			snprintf(error, error_bytes, "%s: guarded path %u is not terminated", path, i);
			return -1;
		}
		roots[i].kind = guarded[i].kind;
		roots[i].path = guarded[i].path;
	}
	out->rule_count = header.rule_count;
	out->alias_count = header.alias_count;
	out->root_count = header.root_count;
	out->rule_bytes = sizeof(struct rule_line);
	out->alias_bytes = sizeof(struct alias_context);
	out->rules = rules;
	out->aliases = aliases;
	out->roots = roots;
	return 0;
}
