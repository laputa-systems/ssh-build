#!/bin/sh
# Create a deterministic DEFLATE zip archive from an explicit file list with the rawzip-based
# tools/make-archive crate (1980-01-01 entry times, unix permissions 755/644 from the file
# list). Usage: make_archive <output.zip> <dir> <file>...
# Building the crate the first time compiles rawzip and flate2; the target directory under
# tools/make-archive/target is reused after that.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
make_archive() {
    archive=$1
    dir=$2
    shift 2
    cargo run --release --quiet --manifest-path "$script_dir/../tools/make-archive/Cargo.toml" -- "$archive" "$dir" "$@"
}
