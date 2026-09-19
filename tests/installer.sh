#!/bin/sh
# Behavioural tests for install.sh — the paths a user actually hits, as opposed to whether the
# script parses. CI runs this; it is also runnable by hand from anywhere.
#
#   sh tests/installer.sh                     # test ../install.sh
#   INSTALL_SH=/tmp/old-install.sh sh tests/installer.sh
#
# `cargo` and `curl` are stubbed, so nothing here touches the network or builds anything. The
# curl stub always fails, which is how "no release has been published yet" is reproduced without
# depending on the repository's release state.

set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
install_sh=${INSTALL_SH:-$here/install.sh}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

mkdir -p "$work/bin"

# Records its arguments, then fabricates the binary `place_binary` expects to find.
cat > "$work/bin/cargo" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$CARGO_ARGS"
root=
prev=
for a in "$@"; do
    [ "$prev" = "--root" ] && root=$a
    prev=$a
done
[ -n "$root" ] || exit 0
mkdir -p "$root/bin"
printf '#!/bin/sh\necho "akey 0.0.0-stub"\n' > "$root/bin/akey"
chmod +x "$root/bin/akey"
STUB

cat > "$work/bin/curl" <<'STUB'
#!/bin/sh
exit 22
STUB
chmod +x "$work/bin/cargo" "$work/bin/curl"

run_installer() {
    : > "$work/cargo-args"
    CARGO_ARGS="$work/cargo-args" \
        PATH="$work/bin:$PATH" \
        AKEY_INSTALL_DIR="$work/install" \
        sh "$install_sh" "$@" >"$work/out" 2>&1 || true
    cat "$work/cargo-args"
}

# 1. No release reachable and no prebuilt binary: fall back to a source build, and that build must
#    NOT pass `--tag`. An empty tag becomes the refspec `+refs/tags/:refs/remotes/origin/tags/`,
#    which cargo rejects — the failure this test exists for.
args=$(run_installer)
case "$args" in
    *--tag*) fail "passed --tag without a resolved tag: $args" ;;
esac
case "$args" in
    *install*) ;;
    *) fail "did not fall back to a source build: ${args:-<no cargo invocation>}" ;;
esac
printf 'ok: unreachable release falls back without --tag\n'

# 2. An explicitly named version must still be passed through, or `--version` would silently
#    install something other than what was asked for.
args=$(run_installer --from-source --version v1.2.3)
case "$args" in
    *"--tag v1.2.3"*) ;;
    *) fail "explicit --version was not passed to cargo: $args" ;;
esac
printf 'ok: explicit --version becomes --tag\n'

# 3. `--from-source` on its own means the default branch, so still no --tag.
args=$(run_installer --from-source)
case "$args" in
    *--tag*) fail "--from-source invented a tag: $args" ;;
esac
printf 'ok: --from-source builds the default branch\n'

printf 'installer tests passed\n'
