# Digger - Installation Guide

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Node.js 18+ (for Workbench UI, optional)

## Installation Methods

### Method 1: cargo install (Recommended)

```bash
cargo install --git https://github.com/digger-determsec/digger --bin digger
```

### Method 2: Build from Source

```bash
git clone https://github.com/digger-determsec/digger.git
cd digger
cargo build --release
```

The binary will be at `target/release/digger`.

### Method 3: Development Build

```bash
git clone https://github.com/digger-determsec/digger.git
cd digger
cargo build
```

The binary will be at `target/debug/digger`.

## Verify Installation

```bash
digger version
# Expected: digger 0.2.0-beta.7

digger validate
# Expected: All checks passed
```

## Workbench (Optional)

```bash
cd workbench
npm install
npm run dev
# Opens at http://localhost:3000
```

## System Requirements

| Platform | Status |
|----------|--------|
| Linux (x86_64) | ✅ Supported |
| macOS (x86_64, aarch64) | ✅ Supported |
| Windows (x86_64) | ✅ Supported |

## Troubleshooting

### "cargo: command not found"
Install Rust via [rustup.rs](https://rustup.rs/).

### "digger: command not found"
Ensure `~/.cargo/bin` is in your PATH, or use `cargo run -- <command>` from the project directory.

### Build fails with "linker not found"
Install platform build tools:
- **Linux**: `sudo apt install build-essential`
- **macOS**: `xcode-select --install`
- **Windows**: Install Visual Studio Build Tools
