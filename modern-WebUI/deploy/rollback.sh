#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=
backup=
while (($#)); do
  case "$1" in
    --simulate-root) root=${2:?missing simulation root}; shift 2 ;;
    --backup) backup=${2:?missing selected backup}; shift 2 ;;
    --help) printf '%s\n' 'usage: rollback.sh --simulate-root ROOT --backup DIR'; exit 0 ;;
    *) printf 'rollback.sh: unsupported argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n $root && -n $backup ]] || { printf '%s\n' 'rollback.sh: simulation root and selected backup are required' >&2; exit 2; }
exec python3 "$here/deployment.py" rollback-sim --root "$root" --backup "$backup"
