#!/usr/bin/env bash
set -euo pipefail
umask 077
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=
package=
backups=
fault=
while (($#)); do
  case "$1" in
    --simulate-root) root=${2:?missing simulation root}; shift 2 ;;
    --package) package=${2:?missing package}; shift 2 ;;
    --backup-dir) backups=${2:?missing private backup directory}; shift 2 ;;
    --fault) fault=${2:?missing fault name}; shift 2 ;;
    --help) printf '%s\n' 'usage: deploy.sh --simulate-root ROOT --package RELEASE.tar --backup-dir DIR [--fault NAME]'; exit 0 ;;
    *) printf 'deploy.sh: unsupported argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -n $root && -n $package && -n $backups ]] || { printf '%s\n' 'deploy.sh: simulation root, package, and backup directory are required' >&2; exit 2; }
if [[ -n $fault ]]; then
  exec python3 "$here/deployment.py" deploy-sim --root "$root" --package "$package" --backup-dir "$backups" --fault "$fault"
fi
exec python3 "$here/deployment.py" deploy-sim --root "$root" --package "$package" --backup-dir "$backups"
