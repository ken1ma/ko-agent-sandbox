#!/bin/sh
# Empties each build cache whose marker file is missing or older than max_age_days, and writes the
# marker into a cache it emptied. Containerfile, at the step that runs this, has why.
#
#   expire-build-cache.sh DIRECTORY...
set -eu

marker=.ko-agent-cache-created
# Below the ages systemd's own tmp.conf gives /tmp (10 days) and /var/tmp (30 days).
max_age_days=7

for cache in "$@"; do
    if [ -z "$(find "${cache}/${marker}" -mmin "-$((max_age_days * 24 * 60))" 2>/dev/null)" ]; then
        find "${cache}" -mindepth 1 -delete
        touch "${cache}/${marker}"
    fi
done
