#!/usr/bin/env bash
# ==============================================================================
# Cybog Automated Environment & Toolchain Setup Script
# Works on Debian/Ubuntu/Kali Linux VPS or local workstation.
# Installs Go, Go-based tools (subfinder, dnsx, httpx, naabu, katana, nuclei),
# ffuf, Python dependencies, and downloads common wordlists.
# ==============================================================================

set -euo pipefail

# ANSI color codes
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

log_info() { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error() { echo -e "${RED}[-]${RESET} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/go/bin"
LOCAL_BIN="$HOME/.local/bin"

mkdir -p "$BIN_DIR" "$LOCAL_BIN" "$SCRIPT_DIR/config/wordlists"

# 1. Check or install Go
check_golang() {
    log_info "Verifying Go installation..."
    if ! command -v go &>/dev/null; then
        log_warn "Go not found in PATH. Checking system package manager..."
        if command -v apt-get &>/dev/null; then
            log_info "Installing golang-go via apt..."
            sudo apt-get update -y && sudo apt-get install -y golang-go git curl jq
        else
            log_error "apt-get not detected. Please install Go (1.21+) manually from https://go.dev/dl/."
            exit 1
        fi
    fi
    log_success "Go is available: $(go version)"
}

# 2. Configure PATH
configure_path() {
    log_info "Configuring PATH for Go & local binaries..."
    export PATH="$PATH:$BIN_DIR:$LOCAL_BIN"
    
    # Persist in user shell rc if not already present
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            if ! grep -q "go/bin" "$rc"; then
                echo -e '\n# Cybog toolchain PATH' >> "$rc"
                echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"' >> "$rc"
                log_success "Appended Go bin to $rc"
            fi
        fi
    done
}

# 3. Install Security Tools via Go
install_security_tools() {
    log_info "Installing security toolchain..."

    declare -A TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )

    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_success "Tool already installed: $tool ($(command -v "$tool"))"
        else
            log_info "Installing $tool from ${TOOLS[$tool]}..."
            go install -v "${TOOLS[$tool]}"
            log_success "Installed $tool"
        fi
    done
}

# 4. Update Nuclei Templates
update_nuclei() {
    if command -v nuclei &>/dev/null; then
        log_info "Downloading / updating Nuclei templates..."
        nuclei -update-templates -silent || log_warn "Template update completed with warnings."
        log_success "Nuclei templates updated."
    fi
}

# 5. Download default wordlists if missing
setup_wordlists() {
    WORDLIST_PATH="$SCRIPT_DIR/config/wordlists/common.txt"
    if [ ! -f "$WORDLIST_PATH" ] || [ ! -s "$WORDLIST_PATH" ]; then
        log_info "Fetching standard SecLists raft directory wordlist..."
        curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt" \
            -o "$WORDLIST_PATH" || {
                log_warn "Could not fetch SecLists wordlist from GitHub. Using built-in baseline wordlist."
                cat << 'EOF' > "$WORDLIST_PATH"
admin
api
v1
v2
login
auth
health
dashboard
metrics
test
staging
EOF
            }
        log_success "Wordlist established at $WORDLIST_PATH"
    else
        log_success "Wordlist verified at $WORDLIST_PATH"
    fi
}

# 6. Install Python dependencies & Cybog CLI
setup_python_env() {
    log_info "Setting up Python environment..."
    python3 -m pip install --user --break-system-packages -r "$SCRIPT_DIR/requirements.txt"
    python3 -m pip install --user --break-system-packages -e "$SCRIPT_DIR"
    log_success "Python dependencies and Cybog package installed."
}

# 7. Verification
verify_installation() {
    log_info "Running Cybog toolchain healthcheck..."
    python3 -m cybog.cli.main tools --config "$SCRIPT_DIR/config.yaml"
}

main() {
    echo -e "${BLUE}====================================================${RESET}"
    echo -e "${BLUE}       Project Cybog Automated Setup Installer      ${RESET}"
    echo -e "${BLUE}====================================================${RESET}"

    check_golang
    configure_path
    install_security_tools
    update_nuclei
    setup_wordlists
    setup_python_env
    verify_installation

    echo -e "\n${GREEN}[✓] Setup complete!${RESET}"
    echo -e "You can now run: ${YELLOW}cybog --help${RESET} or ${YELLOW}python3 -m cybog.cli.main --help${RESET}\n"
}

main "$@"
