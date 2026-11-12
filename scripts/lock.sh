# shellcheck shell=sh disable=SC2154
sources_lock=$script_dir/../sources.lock.json
lock_field() {
    jaq -r --arg name "$1" --arg field "$2" '.inputs[] | select(.name == $name) | .[$field] // empty' "$sources_lock"
}
lock_urls() {
    jaq -r --arg name "$1" '.inputs[] | select(.name == $name) | (.urls // [.url])[]' "$sources_lock"
}
