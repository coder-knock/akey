#!/bin/sh
# akey installer.
#
# Installs the `akey` binary on macOS or Linux, arm64 or x86_64.
# Downloads a prebuilt release when one exists for this platform and falls back to
# building from source with cargo otherwise.
#
#   curl -fsSL https://raw.githubusercontent.com/coder-knock/akey/main/install.sh | sh
#
# Options (or the matching environment variable):
#   --version <tag>     install a specific release tag         (AKEY_VERSION, default: latest)
#   --dir <path>        install into this directory            (AKEY_INSTALL_DIR, default: ~/.local/bin)
#   --from-source       build from source with cargo, skip the download
#   --force             reinstall even if the same version is already present
#   --help
#
# Exit codes: 0 installed, 1 anything went wrong, 2 unsupported platform.

set -eu

REPO="coder-knock/akey"
BIN="akey"
MIN_RUST="1.85"          # edition 2024

# Overridable so the script can be tested against a local "release" directory.
DIST_BASE="${AKEY_DIST_BASE:-https://github.com/${REPO}/releases/download}"

VERSION="${AKEY_VERSION:-latest}"
INSTALL_DIR="${AKEY_INSTALL_DIR:-${HOME}/.local/bin}"
FROM_SOURCE="no"
FORCE="no"

# ---------------------------------------------------------------- output

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')
else
    BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; RESET=''
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---------------------------------------------------------------- args

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --dir) INSTALL_DIR="${2:-}"; shift 2 ;;
        --dir=*) INSTALL_DIR="${1#*=}"; shift ;;
        --from-source) FROM_SOURCE="yes"; shift ;;
        --force) FORCE="yes"; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[ -n "$VERSION" ] || die "--version needs a value"
[ -n "$INSTALL_DIR" ] || die "--dir needs a value"

# ---------------------------------------------------------------- platform

detect_triple() {
    os=$(uname -s 2>/dev/null || echo unknown)
    arch=$(uname -m 2>/dev/null || echo unknown)

    case "$os" in
        Darwin)
            case "$arch" in
                arm64|aarch64) echo "aarch64-apple-darwin" ;;
                x86_64|amd64)  echo "x86_64-apple-darwin" ;;
                *) return 1 ;;
            esac
            ;;
        Linux)
            # Prefer the static musl build: it runs on any distro regardless of glibc.
            case "$arch" in
                aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
                x86_64|amd64)  echo "x86_64-unknown-linux-musl" ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------- downloaders

have() { command -v "$1" >/dev/null 2>&1; }

# fetch <url> <dest>   — returns non-zero on any failure without aborting the script
fetch() {
    if have curl; then
        curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" 2>/dev/null
    elif have wget; then
        wget -q -T 15 -O "$2" "$1" 2>/dev/null
    else
        return 1
    fi
}

# Read the final URL of /releases/latest instead of the JSON API: no jq, no rate limit.
resolve_latest_tag() {
    if have curl; then
        url=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
              "https://github.com/${REPO}/releases/latest" 2>/dev/null) || return 1
    elif have wget; then
        url=$(wget -q -S --spider "https://github.com/${REPO}/releases/latest" 2>&1 \
              | sed -n 's/.*Location: \(.*\)$/\1/p' | tail -1) || return 1
    else
        return 1
    fi
    tag=${url##*/}
    case "$tag" in
        ""|latest|releases) return 1 ;;
    esac
    printf '%s' "$tag"
}

checksum_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
    elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else return 1
    fi
}

# ---------------------------------------------------------------- install from a release

install_from_release() {
    triple=$1
    tag=$2

    asset="${BIN}-${tag}-${triple}.tar.gz"
    url="${DIST_BASE}/${tag}/${asset}"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t akey)
    trap 'rm -rf "$tmp"' EXIT INT TERM

    step "downloading ${asset}"
    if ! fetch "${url}" "${tmp}/${asset}"; then
        say "${DIM}    no prebuilt binary at ${url}${RESET}"
        return 1
    fi

    # Verify before extracting. A checksum we cannot fetch is a checksum we do not skip:
    # silently installing an unverified binary from the network is worse than failing.
    step "verifying sha256"
    if fetch "${url}.sha256" "${tmp}/${asset}.sha256"; then
        expected=$(awk '{print $1}' "${tmp}/${asset}.sha256")
        actual=$(checksum_of "${tmp}/${asset}") || {
            warn "no sha256 tool available; cannot verify the download"
            die "refusing to install an unverified binary (install shasum, sha256sum or openssl)"
        }
        if [ "$expected" != "$actual" ]; then
            die "checksum mismatch for ${asset}
  expected ${expected}
  actual   ${actual}
This is either a corrupted download or a tampered one. Nothing was installed."
        fi
    else
        warn "no checksum published for ${asset}"
    fi

    step "extracting"
    tar -xzf "${tmp}/${asset}" -C "$tmp" || die "could not extract ${asset}"
    src="${tmp}/${BIN}-${tag}-${triple}/${BIN}"
    [ -f "$src" ] || src=$(find "$tmp" -type f -name "$BIN" -perm -u+x 2>/dev/null | head -1)
    [ -n "${src:-}" ] && [ -f "$src" ] || die "the archive did not contain a '$BIN' binary"

    place_binary "$src"
}

# ---------------------------------------------------------------- install from source

install_from_source() {
    have cargo || die "cargo not found. Install Rust from https://rustup.rs and re-run,
or use a platform with a prebuilt binary."

    rustc_version=$(rustc --version 2>/dev/null | awk '{print $2}') || rustc_version=""
    say "${DIM}    rustc ${rustc_version:-unknown} (need >= ${MIN_RUST} for edition 2024)${RESET}"

    step "building from source (this takes a couple of minutes)"
    if [ "$VERSION" = "latest" ]; then
        cargo install --git "https://github.com/${REPO}" --locked --root "${TMP_ROOT:-$HOME/.akey-build}" "$BIN" \
            || die "cargo install failed"
    else
        cargo install --git "https://github.com/${REPO}" --tag "$VERSION" --locked \
            --root "${TMP_ROOT:-$HOME/.akey-build}" "$BIN" || die "cargo install failed"
    fi
    src="${TMP_ROOT:-$HOME/.akey-build}/bin/${BIN}"
    place_binary "$src"
}

# ---------------------------------------------------------------- placing the binary

place_binary() {
    src=$1

    mkdir -p "$INSTALL_DIR" || die "cannot create ${INSTALL_DIR}"
    dest="${INSTALL_DIR}/${BIN}"

    step "installing to ${dest}"
    # Install beside the destination and rename: replacing a running binary in place fails.
    cp "$src" "${dest}.new" || die "cannot write to ${INSTALL_DIR}"
    chmod 755 "${dest}.new"
    mv -f "${dest}.new" "$dest"

    installed=$("$dest" --version 2>/dev/null || echo "")
    [ -n "$installed" ] || die "the installed binary does not run; please report this"
    say "${GREEN}${BOLD}installed${RESET} ${installed} -> ${dest}"

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            say ""
            say "${BOLD}${INSTALL_DIR} is not on your PATH.${RESET} Add it:"
            case "$(basename "${SHELL:-sh}")" in
                zsh)  say "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
                bash) say "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc && exec bash" ;;
                fish) say "  fish_add_path ${INSTALL_DIR}" ;;
                *)    say "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
            esac
            ;;
    esac

    say ""
    say "Next:"
    say "  ${BOLD}akey init --remote <git-url> --device \$(hostname)${RESET}   create a vault"
    say "  ${BOLD}akey --help${RESET}                                          everything else"
}

# ---------------------------------------------------------------- main

say "${BOLD}akey installer${RESET} ${DIM}(macOS and Linux; arm64 and x86_64)${RESET}"

if [ "$FROM_SOURCE" = "yes" ]; then
    install_from_source
    exit 0
fi

if ! triple=$(detect_triple); then
    warn "unsupported platform: $(uname -s 2>/dev/null) / $(uname -m 2>/dev/null)"
    say "Prebuilt binaries are published for macOS (arm64, x86_64) and Linux (x86_64, aarch64)."
    say "On Windows, use the PowerShell installer instead:"
    say "  ${BOLD}irm https://raw.githubusercontent.com/coder-knock/akey/main/install.ps1 | iex${RESET}"
    say ""
    say "If you have cargo, build from source instead:"
    say "  ${BOLD}curl -fsSL .../install.sh | sh -s -- --from-source${RESET}"
    exit 2
fi

say "${DIM}    platform: ${triple}${RESET}"

if [ "$VERSION" = "latest" ]; then
    step "looking up the latest release"
    if ! VERSION=$(resolve_latest_tag); then
        warn "could not reach GitHub to find the latest release"
        install_from_source
        exit 0
    fi
fi
say "${DIM}    version: ${VERSION}${RESET}"

if [ "$FORCE" != "yes" ] && [ -x "${INSTALL_DIR}/${BIN}" ]; then
    current=$("${INSTALL_DIR}/${BIN}" --version 2>/dev/null | awk '{print $2}')
    if [ "v${current}" = "$VERSION" ] || [ "$current" = "${VERSION#v}" ]; then
        say "${GREEN}${BIN} ${VERSION} is already installed${RESET} at ${INSTALL_DIR}/${BIN}"
        say "Use --force to reinstall."
        exit 0
    fi
    say "${DIM}    replacing ${current:-unknown} with ${VERSION}${RESET}"
fi

if ! install_from_release "$triple" "$VERSION"; then
    say ""
    warn "no usable prebuilt binary; falling back to a source build"
    install_from_source
fi
