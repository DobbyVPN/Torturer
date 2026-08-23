#!/usr/bin/env bash
# Capture complete GitHub API stdout/stderr privately and publish only hashes.
set -euo pipefail

if (($# < 4)); then
  printf '%s\n' 'private-gh-api requires timeout, label, output path, and gh arguments' >&2
  exit 2
fi

timeout_seconds=$1
label=$2
output_path=$3
shift 3
if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' 'private-gh-api timeout is invalid' >&2
  exit 2
fi
if ((timeout_seconds > 1800)); then
  printf '%s\n' 'private-gh-api timeout exceeds the hard bound' >&2
  exit 2
fi
if [[ ! "$label" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  printf '%s\n' 'private-gh-api label is invalid' >&2
  exit 2
fi

umask 077
mkdir -p "$(dirname "$output_path")"
chmod 700 "$(dirname "$output_path")"
error_path="${output_path}.stderr.raw.log"
if [[ -e "$output_path" || -L "$output_path" || -e "$error_path" || -L "$error_path" ]]; then
  printf '%s\n' 'private-gh-api refuses to overwrite existing evidence' >&2
  exit 2
fi

# noclobber makes the redirections exclusive; every byte emitted by gh remains
# in the two owner-only files even when timeout terminates the command.
set -C
status=0
timeout --foreground --signal=TERM --kill-after=1s "${timeout_seconds}s" gh api "$@" >"$output_path" 2>"$error_path" || status=$?
set +C

python3 - "$output_path" "$error_path" <<'PY'
import os
import stat
import sys

for raw_path in sys.argv[1:]:
    descriptor = os.open(raw_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o600:
            raise SystemExit("private-gh-api evidence inode is unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
stdout_bytes=$(wc -c <"$output_path" | tr -d '[:space:]')
stderr_bytes=$(wc -c <"$error_path" | tr -d '[:space:]')
stdout_sha256=$(sha256sum "$output_path" | awk '{print $1}')
stderr_sha256=$(sha256sum "$error_path" | awk '{print $1}')
evidence_id=$(python3 -c 'import secrets; print("e" + secrets.token_hex(16)[:31])')
printf 'github_api_evidence kind=%s status=%s id=%s stdout_bytes=%s stdout_sha256=%s stderr_bytes=%s stderr_sha256=%s\n' \
  "$label" "$status" "$evidence_id" "$stdout_bytes" "$stdout_sha256" "$stderr_bytes" "$stderr_sha256"
exit "$status"
