#include "records_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* records.h uses the kernel's type names; only Linux has them, in <linux/types.h>. */
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef int32_t __s32;

/* ko-agent-fs/policy/include, on the include path, which each builder names
 * (ko-agent-fs/policy/tests/bpf_equivalence.rs, container/ko-agent-self-test/Containerfile). */
#include "records.h"

static struct records_root roots[ROOTS];

// Reads like backend.h's read_records, which the controller uses, with the error returned rather than
// fatal and the memory kept for the caller.
int records_file_read(const char *path, struct records_file *out, char *error, size_t error_bytes)
{
	struct records_header header;
	FILE *file = fopen(path, "rb");
	size_t rule_bytes, alias_bytes;
	void *rules = NULL, *aliases = NULL;
	struct guarded_path *guarded = NULL;

	if (!file) {
		snprintf(error, error_bytes, "%s: %s", path, strerror(errno));
		return -1;
	}
	if (fread(&header, sizeof(header), 1, file) != 1 || memcmp(header.magic, RECORDS_MAGIC, 8) != 0) {
		snprintf(error, error_bytes, "%s: not a records file", path);
		goto fail;
	}
	if (header.layout != RECORDS_LAYOUT) {
		snprintf(error, error_bytes, "%s: layout %08x, this build reads %08x", path, header.layout,
			 RECORDS_LAYOUT);
		goto fail;
	}
	if (header.rule_count > RULE_LINES || header.alias_count > ALIASES || header.root_count > GUARDED_PATHS) {
		snprintf(error, error_bytes, "%s: counts %u/%u/%u exceed the policy's bounds", path,
			 header.rule_count, header.alias_count, header.root_count);
		goto fail;
	}
	rule_bytes = (size_t)header.rule_count * sizeof(struct rule_line);
	alias_bytes = (size_t)header.alias_count * sizeof(struct alias_context);
	rules = malloc(rule_bytes + 1);
	aliases = malloc(alias_bytes + 1);
	guarded = calloc(header.root_count + 1, sizeof(*guarded));
	if (!rules || !aliases || !guarded) {
		snprintf(error, error_bytes, "out of memory");
		goto fail;
	}
	if (fread(rules, 1, rule_bytes, file) != rule_bytes || fread(aliases, 1, alias_bytes, file) != alias_bytes ||
	    fread(guarded, sizeof(*guarded), header.root_count, file) != header.root_count || fgetc(file) != EOF) {
		snprintf(error, error_bytes, "%s: its size does not match its counts", path);
		goto fail;
	}
	for (unsigned i = 0; i < header.root_count; i++) {
		if (guarded[i].len >= PATH_BYTES || guarded[i].path[guarded[i].len] != 0) {
			snprintf(error, error_bytes, "%s: guarded path %u is not terminated", path, i);
			goto fail;
		}
		roots[i].kind = guarded[i].kind;
		roots[i].path = guarded[i].path;
	}
	fclose(file);
	out->rule_count = header.rule_count;
	out->alias_count = header.alias_count;
	out->root_count = header.root_count;
	out->rules = rules;
	out->aliases = aliases;
	out->roots = roots;
	return 0;
fail:
	fclose(file);
	free(rules);
	free(aliases);
	free(guarded);
	return -1;
}
