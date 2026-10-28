#!/bin/sh
# Linkage/static/hardening gates for final client bytes. Usage:
#   sh scripts/qualify-binaries.sh <bindir> [macos|linux]
# Fails closed; no weakened checks. On Linux uses readelf/nm, on macOS
# otool/codesign. EXPECT_ARCH overrides the arch assertion.
set -u

dir=${1:?usage: qualify-binaries.sh <bindir>}
flavour=${2:-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')}
arch=${EXPECT_ARCH:-$(uname -m)}

bins=${QUALIFY_BINS:-"ssh ssh-keygen ssh-agent ssh-add sftp scp"}
fails=0

chk() {
    if [ "$1" -ne 0 ]; then
        echo "FAIL: $2" >&2
        fails=$((fails + 1))
    else
        echo "ok: $2"
    fi
}

for b in $bins; do
    f=$dir/$b
    test -x "$f" || { echo "FAIL: $f missing or not executable" >&2; fails=$((fails + 1)); continue; }

    case $b in
        oxish-*)
            ! LC_ALL=C grep -aqiE 'aws-lc|aws_lc|openssl|boringssl|libressl' "$f"; chk $? "$b: no other crypto provider named in the bytes"
            ;;
        sftp|scp)
            ! LC_ALL=C grep -aqE '/bin/ssh($|[^-a-z])' "$f"; chk $? "$b: finds ssh through PATH, no absolute path"
            ;;
    esac

    # No libcrypto/libssl linkage or symbols in any artifact.
    if [ "$flavour" = "macos" ]; then
        non_sys=$(otool -L "$f" | sed '1d' | awk '$1 !~ /^\/(usr\/lib|System\/Library)\// { print $1 }')
        [ -z "$non_sys" ]; chk $? "$b: system-only dylibs"
        undef=$(nm -u "$f" 2>/dev/null | grep -ci "evp\|_RSA\|_EC_KEY\|_BN_new\|libcrypto" || true)
        [ "$undef" -eq 0 ]; chk $? "$b: no libcrypto symbols ($undef)"
        file_out=$(file -b "$f")
        echo "$file_out" | grep -q "$arch"; chk $? "$b: arch $arch"
        otool -hv "$f" | grep -q "PIE"; chk $? "$b: PIE"
        codesign -v "$f" 2>/dev/null; chk $? "$b: valid signature"
        minos=$(otool -l "$f" | awk '/LC_BUILD_VERSION/ { found = 1 } found && $1 == "minos" { print $2; exit }')
        floor=${MACOS_FLOOR:-14.0}
        [ -n "$minos" ] && [ "$(printf '%s\n%s\n' "$minos" "$floor" | sort -V | tail -n 1)" = "$floor" ]; chk $? "$b: deployment target $minos within the documented floor $floor"
    else
        interp=$(readelf -l "$f" 2>/dev/null | grep -c "INTERP" || true)
        [ "$interp" -eq 0 ]; chk $? "$b: static, no PT_INTERP"
        readelf -h "$f" 2>/dev/null | grep -q "Type:.*DYN"; chk $? "$b: position independent (static-pie)"
        needed=$(readelf -d "$f" 2>/dev/null | grep -c "NEEDED" || true)
        [ "$needed" -eq 0 ]; chk $? "$b: static, no DT_NEEDED"
        undef=$(nm -D "$f" 2>/dev/null | grep -ci "evp\|RSA_\|EC_KEY\|BN_new\|libcrypto\|libssl" || true)
        [ "$undef" -eq 0 ]; chk $? "$b: no libcrypto symbols ($undef)"
        segments=$(readelf -lW "$f" 2>/dev/null)
        flags_of() { printf '%s\n' "$segments" | awk -v kind="$1" '$1 == kind { f = ""; for (i = 7; i < NF; i++) f = f $i; print f }'; }
        stack=$(flags_of GNU_STACK)
        [ -n "$stack" ]; chk $? "$b: has a GNU_STACK header"
        case $stack in *E*) false ;; *) true ;; esac; chk $? "$b: non-executable stack ($stack)"
        [ -n "$(flags_of GNU_RELRO)" ]; chk $? "$b: has a GNU_RELRO segment"
        wx=$(flags_of LOAD | grep -c 'W.*E\|E.*W' || true)
        [ "$wx" -eq 0 ]; chk $? "$b: no writable and executable load segment"
        readelf -dW "$f" 2>/dev/null | grep -q TEXTREL; [ $? -ne 0 ]; chk $? "$b: no text relocations"
        readelf -S "$f" | grep -q "\.note\.gnu\.property" && echo "ok: $b: property notes present" || echo "note: $b: no property notes"
        file_out=$(file -b "$f")
        echo "info: $b: $file_out"
        case $arch in
            x86_64|amd64) elf_arch="x86-64" ;;
            aarch64|arm64) elf_arch="ARM aarch64" ;;
            *) elf_arch=$arch ;;
        esac
        echo "$file_out" | grep -q "$elf_arch"; chk $? "$b: arch $elf_arch"
        echo "$file_out" | grep -qi "static"; chk $? "$b: statically linked"
    fi
done

[ "$fails" -eq 0 ] || { echo "$fails qualifying check(s) failed" >&2; exit 1; }
echo "all qualify checks passed for $dir ($flavour/$arch)"
