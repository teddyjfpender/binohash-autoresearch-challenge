#!/usr/bin/env bash
# Recorded instances must still build byte for byte, checked inside the build sandbox.
#
# verify_submissions.py imports the builders, which are submission code. This runs it the way
# benchmark.sh runs a build: read-only filesystem, no network, an unprivileged uid.
set -euo pipefail
cd "$(dirname "$0")/../.."
python_bin="$(python3 -c 'import sys; print(sys.executable)')"
command=( "${python_bin}" -I -B tools/verify_submissions.py )
if command -v bwrap >/dev/null 2>&1; then
  bw=( bwrap )
  if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    bw=( sudo -n bwrap )
  elif command -v setpriv >/dev/null 2>&1; then
    bw=( setpriv --no-new-privs bwrap )
  fi
  exec "${bw[@]}" --ro-bind / / --dev /dev --ro-bind /proc /proc --chdir "$(pwd -P)" \
    --unshare-user --unshare-net --unshare-ipc --unshare-uts --unshare-cgroup \
    --cap-drop ALL --new-session --die-with-parent --uid 65534 --gid 65534 -- "${command[@]}"
elif [[ "$(uname -s)" == "Darwin" ]] && command -v sandbox-exec >/dev/null 2>&1; then
  exec sandbox-exec -p '(version 1)(allow default)(deny file-write*)(allow file-write* (subpath "/dev"))(deny network*)' "${command[@]}"
fi
echo "!! no sandbox available; checking the pins UNCONFINED" >&2
exec "${command[@]}"
