#!/usr/bin/env bash
# One-time setup. The evaluator and the builders need Python 3.10 or newer and nothing else.
# This script runs no builder code.
#
#   ./setup.sh          check Python; on Linux, install bubblewrap for the build sandbox
#   ./setup.sh --core   also build tools/core (needs a Rust toolchain and a C++ compiler)
set -euo pipefail
cd "$(dirname "$0")"

python="${PYTHON:-python3}"
if ! command -v "${python}" >/dev/null 2>&1 || ! "${python}" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  echo "!! Python 3.10 or newer is required (found: $("${python}" --version 2>&1 || echo none))" >&2
  exit 1
fi
echo "python: $("${python}" --version)"

if [[ "$(uname -s)" == "Linux" ]] && ! command -v bwrap >/dev/null 2>&1; then
  sudo=""
  if [[ ${EUID:-$(id -u)} -ne 0 ]] && command -v sudo >/dev/null 2>&1; then sudo="sudo"; fi
  if command -v apt-get >/dev/null 2>&1; then
    ${sudo} apt-get update -qq && ${sudo} apt-get install -y -qq bubblewrap
  else
    echo "!! bubblewrap is not installed; builders will run unconfined (install it with your package manager)" >&2
  fi
fi
if command -v bwrap >/dev/null 2>&1; then
  echo "sandbox: bubblewrap"
elif [[ "$(uname -s)" == "Darwin" ]] && command -v sandbox-exec >/dev/null 2>&1; then
  echo "sandbox: sandbox-exec (write and network confinement only; see SECURITY.md)"
else
  echo "sandbox: none"
fi

if [[ "${1:-}" == "--core" ]]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env" 2>/dev/null || true
  if ! command -v cargo >/dev/null 2>&1; then
    echo "!! --core needs a Rust toolchain (https://rustup.rs)" >&2
    exit 1
  fi
  cargo build --release --locked --manifest-path tools/core/Cargo.toml
  echo "core: tools/core/target/release/cchk"
fi
