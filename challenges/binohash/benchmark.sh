#!/usr/bin/env bash
# Build and evaluate one instance (spec/DESIGN.md, section 3).
#
#   1. Remove any instance.json and score.json, so nothing can be pre-seeded.
#   2. Run the builders (UNTRUSTED: `builders/` is submission code) with the manifest's BINO_*
#      knobs, confined: read-only filesystem, no network, no capabilities, an unprivileged uid,
#      and a throwaway scratch directory as the only writable path. Linux uses bubblewrap, macOS
#      sandbox-exec; with neither it runs unconfined and says so. The build runs in its own
#      process group, which is killed afterwards.
#   3. Copy instance.json out of the scratch directory if it is a regular, non-empty file.
#   4. Run the evaluator (TRUSTED: `evaluator/`), a separate process that imports no builder
#      code and reads the instance as hostile data. It writes score.json.
#
# BINO_SPEC names the track's spec (default bh1-standard). BINO_STAGE=build stops after step 3,
# which is how the judge runs it. Arguments are passed to the evaluator, for example
# `--stage screen`, `--lanes 8`, `--seed <hex>` or `--core tools/core/target/release/cchk`.
set -euo pipefail
cd "$(dirname "$0")"

python="${PYTHON:-python3}"
if ! "${python}" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  echo "!! Python 3.10 or newer is required; run ./setup.sh" >&2
  exit 1
fi
python_bin="$("${python}" -c 'import sys; print(sys.executable)')"
spec="${BINO_SPEC:-bh1-standard}"
stage="${BINO_STAGE:-all}"
repo_root="$(pwd -P)"

# 1. Clean slate.
rm -f instance.json score.json

# 2. The untrusted stage.
scratch="$(cd "$(mktemp -d)" && pwd -P)"
chmod 0777 "${scratch}"
runner=( "${python_bin}" -I -B "${repo_root}/evaluator/run_builder.py" )
via_sudo=0
if command -v bwrap >/dev/null 2>&1; then
  bw=( bwrap )
  if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    bw=( sudo -n --preserve-env bwrap )
    via_sudo=1
  elif command -v setpriv >/dev/null 2>&1; then
    bw=( setpriv --no-new-privs bwrap )
  fi
  run_build=(
    "${bw[@]}"
      --ro-bind / / --dev /dev --ro-bind /proc /proc
      --bind "${scratch}" "${scratch}" --chdir "${scratch}"
      --setenv TMPDIR "${scratch}" --setenv BINO_OUT "${scratch}" --unsetenv BAC_LEDGER_KEY
      --unshare-user --unshare-net --unshare-ipc --unshare-uts --unshare-cgroup
      --cap-drop ALL --new-session --die-with-parent
      --uid 65534 --gid 65534
      -- "${runner[@]}"
  )
elif [[ "$(uname -s)" == "Darwin" ]] && command -v sandbox-exec >/dev/null 2>&1; then
  profile="(version 1)(allow default)(deny file-write*)(allow file-write* (subpath \"${scratch}\"))(allow file-write* (subpath \"/dev\"))(deny network*)"
  run_build=(
    sandbox-exec -p "${profile}"
      /usr/bin/env -u BAC_LEDGER_KEY TMPDIR="${scratch}" BINO_OUT="${scratch}" "${runner[@]}"
  )
else
  echo "!! no sandbox available (bubblewrap or sandbox-exec); running the builders UNCONFINED" >&2
  run_build=( /usr/bin/env -u BAC_LEDGER_KEY BINO_OUT="${scratch}" "${runner[@]}" )
fi

group=""
reap() {
  [[ -n "${group}" ]] || return 0
  if [[ "${via_sudo}" -eq 1 ]]; then
    sudo -n kill -KILL -"${group}" 2>/dev/null || true
  else
    kill -KILL -"${group}" 2>/dev/null || true
  fi
}
cleanup() {
  reap
  [[ -z "${scratch:-}" ]] || rm -rf "${scratch}" 2>/dev/null || true
}
trap cleanup EXIT

if command -v setsid >/dev/null 2>&1; then
  setsid "${run_build[@]}" &
else
  set -m
  "${run_build[@]}" &
fi
build_pid=$!
group="${build_pid}"
set +e
wait "${build_pid}"
build_status=$?
set -e
reap
group=""
set +m 2>/dev/null || true

if [[ "${build_status}" -ne 0 ]]; then
  echo "!! the builders exited with status ${build_status}" >&2
  exit "${build_status}"
fi

# 3. Take the one output: a regular, non-empty file and nothing else.
if [[ -f "${scratch}/instance.json" && ! -L "${scratch}/instance.json" && -s "${scratch}/instance.json" ]]; then
  cp "${scratch}/instance.json" ./instance.json
fi
rm -rf "${scratch}"; scratch=""
if [[ ! -s instance.json ]]; then
  echo "!! the builders did not produce instance.json" >&2
  exit 1
fi
if [[ "${stage}" == "build" ]]; then
  echo "build stage done: instance.json ($(wc -c < instance.json | tr -d ' ') bytes)"
  exit 0
fi

# 4. The trusted stage: a separate process that imports no builder code.
exec ./evaluate.sh --root . --spec "${spec}" "$@"
