#!/usr/bin/env bash
# Run the trusted evaluator on an instance that is already built:
#
#   ./evaluate.sh --root DIR --spec bh1-standard [--stage screen|full] [--seed HEX] [--core PATH]
#
# DIR holds instance.json; score.json is written beside it. No builder code is imported. -I keeps
# the environment and the working directory off Python's import path.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -P)"
python="${PYTHON:-python3}"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root|--vectors|--core) args+=( "$1" "$(cd "$(dirname "$2")" && pwd -P)/$(basename "$2")" ); shift 2 ;;
    *) args+=( "$1" ); shift ;;
  esac
done
cd "${here}/evaluator"
exec "${python}" -I -B -c 'import sys; sys.path.insert(0, "."); from bh.evaluate import main; sys.exit(main())' "${args[@]}"
