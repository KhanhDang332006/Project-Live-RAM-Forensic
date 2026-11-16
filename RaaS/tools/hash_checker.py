#!/usr/bin/env bash
#
# hash_checker.sh
# Non-destructive SHA256 verification for the Double Extortion Simulation Lab.
#
# Usage:
#   ./hash_checker.sh verify <target_directory> <manifest>
#   ./hash_checker.sh compare <directory_a> <directory_b>
#
# The manifest format is the standard output of:
#   find . -type f -print0 | sort -z | xargs -0 sha256sum
#
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME verify <target_directory> <sha256_manifest>
      Verify files under target_directory against a previously generated
      sha256sum manifest. Paths in the manifest are resolved from the
      target directory.

  $SCRIPT_NAME compare <directory_a> <directory_b>
      Compare SHA256 hashes of all regular files in two directories.
      Relative paths must match.

Examples:
  $SCRIPT_NAME verify ~/lab/recovery-demo \\
    ~/lab/evidence/original_hashes.txt

  $SCRIPT_NAME compare ~/lab/data \\
    ~/lab/backup/data

Notes:
  - This script only reads files; it does not modify them.
  - Use a trusted manifest generated before the simulation.
EOF
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

verify_manifest() {
    local target_dir="$1"
    local manifest="$2"

    [[ -d "$target_dir" ]] || die "Target directory does not exist: $target_dir"
    [[ -f "$manifest" ]] || die "Manifest does not exist: $manifest"
    require_command sha256sum

    echo "[INFO] Target   : $(realpath "$target_dir")"
    echo "[INFO] Manifest : $(realpath "$manifest")"
    echo "[INFO] Verifying SHA256 checksums..."
    echo

    # sha256sum resolves manifest paths relative to the current directory.
    if (cd "$target_dir" && sha256sum --check -- "$manifest"); then
        echo
        echo "[PASS] All files match the reference manifest."
    else
        local status=$?
        echo
        echo "[FAIL] One or more files are missing or have a different hash."
        return "$status"
    fi
}

compare_directories() {
    local dir_a="$1"
    local dir_b="$2"
    local tmp_a tmp_b

    [[ -d "$dir_a" ]] || die "Directory A does not exist: $dir_a"
    [[ -d "$dir_b" ]] || die "Directory B does not exist: $dir_b"
    require_command sha256sum
    require_command find
    require_command sort
    require_command diff

    tmp_a="$(mktemp)"
    tmp_b="$(mktemp)"
    trap 'rm -f "${tmp_a:-}" "${tmp_b:-}"' RETURN

    (
        cd "$dir_a"
        find . -type f -print0 | sort -z | xargs -0 -r sha256sum
    ) > "$tmp_a"

    (
        cd "$dir_b"
        find . -type f -print0 | sort -z | xargs -0 -r sha256sum
    ) > "$tmp_b"

    echo "[INFO] Directory A: $(realpath "$dir_a")"
    echo "[INFO] Directory B: $(realpath "$dir_b")"
    echo "[INFO] Comparing file lists and SHA256 hashes..."
    echo

    if diff -u "$tmp_a" "$tmp_b"; then
        echo "[PASS] Files and SHA256 hashes are identical."
    else
        echo "[FAIL] Differences found (missing files, extra files, or changed content)."
        return 1
    fi
}

main() {
    [[ $# -ge 1 ]] || { usage; exit 2; }

    case "$1" in
        verify)
            [[ $# -eq 3 ]] || { usage; exit 2; }
            verify_manifest "$2" "$3"
            ;;
        compare)
            [[ $# -eq 3 ]] || { usage; exit 2; }
            compare_directories "$2" "$3"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            die "Unknown mode: $1"
            ;;
    esac
}

main "$@"

