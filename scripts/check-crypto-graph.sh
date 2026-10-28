#!/bin/sh
# Fail if a cryptography provider other than Graviola is in the server's
# release dependency graph or anywhere in Cargo.lock.
#   sh scripts/check-crypto-graph.sh            check vendor/oxish
#   sh scripts/check-crypto-graph.sh --selftest prove the check rejects seeded providers
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
manifest=$root_dir/vendor/oxish/Cargo.toml
lock=$root_dir/vendor/oxish/Cargo.lock

providers='aws-lc|aws-lc-rs|aws-lc-sys|aws-lc-fips-sys|openssl|openssl-sys|openssl-src|boring|boring-sys|boringssl|libressl|ring|rustls|rustls-.*|native-tls|mbedtls|mbedtls-sys|wolfssl|wolfssl-sys|nss|nss-sys|gnutls|security-framework|security-framework-sys|schannel'
primitives='sha1|sha2|sha3|hmac|hkdf|aes|aes-gcm|chacha20|chacha20poly1305|poly1305|curve25519-dalek|ed25519-dalek|x25519-dalek|p256|p384|p521|ecdsa|rsa|ml-kem|pqcrypto.*|libcrux.*|subtle'

fail() { echo "check-crypto-graph: $*" >&2; exit 1; }

scan_names() {
    pattern=$1
    awk -v re="^($pattern)\$" '$1 ~ re { print $1 }' | sort -u
}

check_release_graph() {
    hits=$(scan_names "$providers|$primitives") || true
    [ -z "$hits" ] || fail "prohibited crates in the release graph: $(echo $hits)"
}

check_lock() {
    hits=$(sed -n 's/^name = "\(.*\)"$/\1/p' | scan_names "$providers") || true
    [ -z "$hits" ] || fail "prohibited providers in Cargo.lock: $(echo $hits)"
}

if [ "${1:-}" = --selftest ]; then
    for seeded in aws-lc-rs openssl-sys ring rustls sha2 chacha20poly1305; do
        if printf 'oxish v0.2.0\n%s v1.0.0\n' "$seeded" | check_release_graph 2>/dev/null; then
            fail "selftest: $seeded was not rejected"
        fi
    done
    if printf 'name = "ring"\n' | check_lock 2>/dev/null; then
        fail "selftest: ring in Cargo.lock was not rejected"
    fi
    echo "selftest ok: seeded providers are rejected"
    exit 0
fi

command -v cargo >/dev/null || fail "cargo not found"
cd "$root_dir"
cargo tree --locked --manifest-path "$manifest" -p oxish --edges normal,build --target all --prefix none \
    | sed 's/ v[0-9].*$//' | check_release_graph
check_lock < "$lock"
cargo tree --locked --manifest-path "$manifest" -p oxish --edges normal,build --target all --prefix none \
    | grep -q '^graviola v.*vendor/graviola' || fail "graviola does not resolve to the patched vendor/graviola"
graviola=$(sed -n '/^name = "graviola"$/{n;s/^version = "\(.*\)"$/\1/p;}' "$lock")
[ -n "$graviola" ] || fail "graviola is not in Cargo.lock"
echo "crypto graph ok: graviola $graviola is the only provider (release graph and Cargo.lock)"
