# shellcheck shell=sh
# The executables of the oxish archive. Source this file; do not run it.
#
# The client crate (client/) builds `oxish`, `oxish-sftp` and `oxish-scp` besides `oxish-keygen`.
# OXISH_CLIENT_REQUIRED=1 makes a missing one fail the build, the build record, packaging and the
# release job; with 0 the archive carries whichever of them exist.
OXISH_CLIENT_REQUIRED=1

# oxish_bins DIR: print the archive's executables that DIR holds, clients first.
# oxish-server and oxish-keygen are always expected; oxish-session is listed when the server build
# produced it. Missing required files are reported by the callers' own existence checks.
oxish_bins() {
    oxish_dir=$1
    oxish_list="oxish-server oxish-session oxish-keygen"
    if [ ! -x "$oxish_dir/oxish-session" ]; then
        oxish_list="oxish-server oxish-keygen"
    fi
    for oxish_client in oxish-scp oxish-sftp oxish; do
        if [ -x "$oxish_dir/$oxish_client" ]; then
            oxish_list="$oxish_client $oxish_list"
        elif [ "$OXISH_CLIENT_REQUIRED" = 1 ]; then
            echo "oxish_bins: $oxish_client is required and $oxish_dir/$oxish_client is missing" >&2
            return 1
        fi
    done
    printf '%s\n' "$oxish_list"
}
