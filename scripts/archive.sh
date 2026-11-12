make_archive() {
    archive=$1
    dir=$2
    shift 2
    if tar --version 2>/dev/null | grep -q 'GNU tar'; then
        (cd "$dir" && tar --mtime=@0 --owner=0 --group=0 --numeric-owner -cJf "$archive" "$@")
    else
        (cd "$dir" && tar --uid 0 --gid 0 --uname root --gname root --numeric-owner -cJf "$archive" "$@")
    fi
}
