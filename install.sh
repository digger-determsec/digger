#!/bin/bash
# Digger — Deterministic Blockchain Security Platform
# Install script for macOS and Linux
#
# Usage: curl -fsSL https://raw.githubusercontent.com/digger-determsec/digger/main/install.sh | bash

set -e

REPO="digger-determsec/digger"
BINARY="digger"
INSTALL_DIR="${DIGGER_INSTALL_DIR:-$HOME/.digger/bin}"
GITHUB_URL="https://github.com/${REPO}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[digger]${NC} $1"; }
ok()    { echo -e "${GREEN}[digger]${NC} $1"; }
warn()  { echo -e "${YELLOW}[digger]${NC} $1"; }
error() { echo -e "${RED}[digger]${NC} $1"; exit 1; }

detect_platform() {
    local os arch
    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="macos" ;;
        MINGW*|MSYS*|CYGWIN*)  os="windows" ;;
        *)          error "Unsupported OS: $(uname -s)"
    esac
    case "$(uname -m)" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)   arch="aarch64" ;;
        *)               error "Unsupported architecture: $(uname -m)"
    esac
    echo "${os}_${arch}"
}

get_latest_version() {
    curl -sL --max-time 10 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | \
        grep '"tag_name"' | head -1 | sed -E 's/.*"v?([^"]+)".*/\1/' || echo ""
}

download_binary() {
    local version="$1"
    local platform="$2"
    local ext=""
    [[ "$platform" == *"windows"* ]] && ext=".exe"

    # Try platform-specific name first, then generic name
    local filenames=("digger-${platform}${ext}" "digger${ext}")
    local dest="${INSTALL_DIR}/${BINARY}${ext}"

    mkdir -p "$INSTALL_DIR"

    for filename in "${filenames[@]}"; do
        local url="${GITHUB_URL}/releases/download/v${version}/${filename}"
        info "Trying ${filename}..."

        local http_code
        http_code=$(curl -sL -w "%{http_code}" -o "$dest" --max-time 120 "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            # Verify the downloaded file is actually a binary, not HTML
            if file "$dest" 2>/dev/null | grep -qi "text\|html\|ascii"; then
                rm -f "$dest"
                continue
            fi
            chmod +x "$dest"
            return 0
        fi
        rm -f "$dest"
    done

    return 1
}

setup_path() {
    local shell_rc=""
    [[ -f "$HOME/.zshrc" ]]   && shell_rc="$HOME/.zshrc"
    [[ -f "$HOME/.bashrc" ]]  && shell_rc="$HOME/.bashrc"
    [[ -f "$HOME/.bash_profile" ]] && shell_rc="$HOME/.bash_profile"

    if [[ -n "$shell_rc" ]]; then
        if ! grep -q "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# Digger" >> "$shell_rc"
            echo "export PATH=\"\$HOME/.digger/bin:\$PATH\"" >> "$shell_rc"
            info "Added $INSTALL_DIR to PATH in $shell_rc"
            warn "Run 'source $shell_rc' or restart your terminal"
        fi
    fi
    export PATH="$INSTALL_DIR:$PATH"
}

build_from_source() {
    info "No prebuilt binary available. Building from source..."

    if ! command -v cargo &>/dev/null; then
        error "Rust/cargo not found. Install from https://rustup.rs first, then retry."
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    info "Cloning to $tmpdir..."
    git clone --depth 1 "$GITHUB_URL" "$tmpdir" 2>/dev/null

    info "Building release binary (this may take a few minutes)..."
    cd "$tmpdir"
    cargo build --release --bin digger 2>/dev/null
    cargo build --release --bin digger-api 2>/dev/null

    mkdir -p "$INSTALL_DIR"
    cp target/release/digger "$INSTALL_DIR/digger"
    cp target/release/digger-api "$INSTALL_DIR/digger-api" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/digger"
    chmod +x "$INSTALL_DIR/digger-api" 2>/dev/null || true

    cd /
    rm -rf "$tmpdir"
}

verify() {
    local ext=""
    [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && ext=".exe"
    if [[ -x "${INSTALL_DIR}/${BINARY}${ext}" ]]; then
        ok "Digger installed to ${INSTALL_DIR}/${BINARY}${ext}"
    else
        error "Installation failed — binary not found"
    fi
}

print_usage() {
    echo ""
    echo -e "${GREEN}Digger — Deterministic Blockchain Security Platform${NC}"
    echo ""
    echo "  Scan:"
    echo "    digger scan --code '<solidity>' --lang solidity"
    echo ""
    echo "  Synthesize:"
    echo "    digger synthesize --code '<solidity>' --lang solidity"
    echo ""
    echo "  Benchmarks:"
    echo "    digger benchmark"
    echo ""
    echo "  Dashboard:"
    echo "    digger-api"
    echo "    open http://localhost:3000"
    echo ""
    echo "  Docs: ${GITHUB_URL}"
    echo ""
}

main() {
    echo ""
    info "Installing Digger..."

    local platform
    platform=$(detect_platform)
    info "Detected platform: $platform"

    # Try downloading prebuilt binary
    local version
    version=$(get_latest_version)

    local downloaded=false
    if [[ -n "$version" ]]; then
        info "Latest release: v${version}"
        if download_binary "$version" "$platform"; then
            downloaded=true
            ok "Downloaded v${version}"
        else
            warn "Download failed (v${version} not available for ${platform})"
        fi
    else
        warn "No releases found on GitHub"
    fi

    # Fall back to building from source
    if [[ "$downloaded" == false ]]; then
        build_from_source
    fi

    setup_path
    verify
    print_usage
}

main "$@"
