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
        # Git Bash maps NTFS ACLs to synthetic POSIX mode bits, so a file
        # created under ``umask 077`` can still report 0666 through fstat.
        # The runner's private temp directory and inherited Windows ACL are
        # the confidentiality boundary there; keep the strict mode check on
        # POSIX while still requiring a regular file on every platform.
        if not stat.S_ISREG(details.st_mode) or (
            os.name != "nt" and stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise SystemExit("private-gh-api evidence file is unsafe")
        # Windows' FlushFileBuffers rejects a read-only CRT descriptor with
        # EBADF; the producer already closed the redirected file before this
        # verification opens it, so the read-only check does not need a flush
        # on that platform.  POSIX keeps the explicit durability barrier.
        if os.name != "nt":
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
if ((status != 0)); then
  # Keep the complete stderr bytes in the owner-only file above, but publish a
  # small safe classification so a failed API call is diagnosable from the
  # hosted job log without exposing credentials, URLs, or private paths.
  python3 - "$error_path" <<'PY'
import re
import sys
from pathlib import Path

payload = Path(sys.argv[1]).read_bytes()
reasons = []
for raw_line in payload.decode("utf-8", "replace").splitlines():
    safe_line = re.sub(r"https?://[^\s]+", "<url>", raw_line)
    safe_line = re.sub(
        r"(?i)\b(?:token|key|secret|password|authorization)\b\s*[:=]\s*\S+",
        "<redacted>",
        safe_line,
    )
    safe_line = re.sub(r"(?:[A-Za-z]:)?[\\/][^\s,;)]*", "<path>", safe_line)
    safe_line = re.sub(r"(?i)\b[0-9a-f]{32,}\b", "<hex>", safe_line)
    safe_line = re.sub(r"\s+", " ", safe_line).strip()
    if re.search(
        r"(?i)\b(?:gh:|http|error|failed|forbidden|unauthor|permission|rate limit|not found|bad gateway|timed out|timeout|connection|api)\b",
        safe_line,
    ):
        reasons.append(safe_line[:240])
print("github_api_error_reason=" + (" | ".join(reasons[:4]) if reasons else "unclassified"))
PY
fi
exit "$status"
