#!/bin/bash
# Drop the proto-fuzz harnesses + corpus generators into a QEMU tree.
#
# Files in this repo mirror the QEMU tree layout exactly, so applying is
# just a recursive copy. Modified upstream files (fuzz.c, fuzz.h,
# meson.build, qtest_wrappers.c, libqtest.c) are full files that
# OVERWRITE the upstream copies.
#
# Usage:
#   ./apply.sh                     # default target: ~/qemu
#   ./apply.sh /path/to/qemu       # explicit target
#   ./apply.sh /path/to/qemu --dry-run

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_DIR="${1:-$HOME/qemu}"
DRY_RUN=""
[[ "$2" == "--dry-run" ]] && DRY_RUN="--dry-run"

if [[ ! -d "$QEMU_DIR" ]]; then
    echo "ERROR: $QEMU_DIR does not exist" >&2
    exit 1
fi

# Sanity check: this should look like a QEMU tree.
if [[ ! -f "$QEMU_DIR/configure" ]] || [[ ! -d "$QEMU_DIR/tests/qtest/fuzz" ]]; then
    echo "ERROR: $QEMU_DIR doesn't look like a QEMU source tree" >&2
    echo "       (expected configure + tests/qtest/fuzz/ to exist)" >&2
    exit 1
fi

echo "Source repo:  $REPO_DIR"
echo "QEMU tree:    $QEMU_DIR"
echo

# Show what's about to land (and on dry-run, stop here).
echo "Files that will be copied / overwritten:"
(cd "$REPO_DIR" && find tests scripts -type f \! -name '.DS_Store') | sed 's/^/    /'
echo

if [[ -n "$DRY_RUN" ]]; then
    echo "(dry-run; nothing copied)"
    exit 0
fi

# Optional pre-apply backup of the 5 files we know we modify.
BACKUP_DIR="$QEMU_DIR/.proto-fuzz-backup-$(date +%s)"
mkdir -p "$BACKUP_DIR"
for f in tests/qtest/fuzz/fuzz.c tests/qtest/fuzz/fuzz.h \
         tests/qtest/fuzz/meson.build tests/qtest/fuzz/qtest_wrappers.c \
         tests/qtest/libqtest.c; do
    if [[ -f "$QEMU_DIR/$f" ]]; then
        mkdir -p "$BACKUP_DIR/$(dirname "$f")"
        cp "$QEMU_DIR/$f" "$BACKUP_DIR/$f"
    fi
done
echo "Backed up upstream copies to: $BACKUP_DIR"

# Recursive copy. Don't use rsync to avoid a non-portable dependency.
(cd "$REPO_DIR" && find tests scripts -type f \! -name '.DS_Store') | while read -r rel; do
    install -m 644 "$REPO_DIR/$rel" "$QEMU_DIR/$rel"
done

# Make python generators executable in the destination, matching the
# repo's mode bits.
chmod +x "$QEMU_DIR"/scripts/oss-fuzz/gen_virtio_*_corpus.py 2>/dev/null || true

echo
echo "Done. To build:    $REPO_DIR/build.sh $QEMU_DIR"
echo "If you ever need to roll back, restore from: $BACKUP_DIR"
