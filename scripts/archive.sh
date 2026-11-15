#!/bin/sh
make_archive() (
    set -eu
    archive=$1
    dir=$2
    shift 2
    members=$(printf '%s\n' "$@" | LC_ALL=C sort)
    set -- $members
    stage=$(mktemp -d "${archive}.stage.XXXXXX")
    trap 'rm -rf "$stage"' EXIT
    for member do
        mkdir -p "$stage/$(dirname "$member")"
        cp "$dir/$member" "$stage/$member"
        if [ -x "$dir/$member" ]; then
            chmod 755 "$stage/$member"
        else
            chmod 644 "$stage/$member"
        fi
        TZ=UTC touch -t 197001010000 "$stage/$member"
    done
    case $(uname -s) in
        Darwin) tar --format ustar --no-xattrs --no-acls --no-fflags --uid 0 --gid 0 --uname '' --gname '' -cJf "$archive" -C "$stage" "$@" ;;
        *) tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cJf "$archive" -C "$stage" "$@" ;;
    esac
)
