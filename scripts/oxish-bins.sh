# shellcheck shell=sh
# The executables of the oxish archive. Source this file; do not run it.
#
# The interactive client crate (client/) builds `oxish` once its CLI lands. Until then the archive
# carries whatever of it exists. Set OXISH_CLIENT_REQUIRED=1 to make a missing `oxish` fail the
# build, the build record, packaging and the release job.
OXISH_CLIENT_REQUIRED=1

# oxish_bins DIR: print the archive's executables that DIR holds, client first.
# oxish-server and oxish-keygen are always expected; oxish-session is listed when the server build
# produced it. Missing required files are reported by the callers' own existence checks.
oxish_bins() {
    oxish_dir=$1
    oxish_list="oxish-server oxish-session oxish-keygen"
    if [ ! -x "$oxish_dir/oxish-session" ]; then
        oxish_list="oxish-server oxish-keygen"
    fi
    if [ -x "$oxish_dir/oxish" ]; then
        oxish_list="oxish $oxish_list"
    elif [ "$OXISH_CLIENT_REQUIRED" = 1 ]; then
        echo "oxish_bins: the oxish client is required and $oxish_dir/oxish is missing" >&2
        return 1
    fi
    printf '%s\n' "$oxish_list"
}
