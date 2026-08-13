#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "==================================="
echo "proxyprism Setup Script"
echo "==================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    echo "Please run: sudo ./setup.sh"
    exit 1
fi

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    else
        DISTRO=$(uname -s)
    fi
    echo "Detected distribution: $DISTRO"
}

# Install dependencies based on distribution
install_dependencies() {
    echo ""
    echo "Checking and installing dependencies..."
    
    # Normalize distro name using ID_LIKE fallback
    local distro_family="$DISTRO"
    if [ -n "$DISTRO_LIKE" ]; then
        case "$DISTRO_LIKE" in
            *ubuntu*|*debian*) distro_family="debian" ;;
            *fedora*) distro_family="fedora" ;;
            *rhel*|*centos*) distro_family="rhel" ;;
            *arch*) distro_family="arch" ;;
            *suse*) distro_family="opensuse" ;;
        esac
    fi
    
    case "$distro_family" in
        ubuntu|debian|linuxmint|pop|elementary|zorin|kali|raspbian|mx|antix|deepin|lmde)
            echo "Using apt package manager..."
            apt-get update -qq
            # iptables is required
            apt-get install -y iptables
            ;;
        fedora)
            echo "Using dnf package manager..."
            dnf install -y iptables
            ;;
        rhel|centos|rocky|almalinux)
            echo "Using yum package manager..."
            yum install -y iptables
            ;;
        arch|manjaro|endeavouros|garuda)
            echo "Using pacman package manager..."
            pacman -Sy --noconfirm iptables
            ;;
        opensuse*|sles)
            echo "Using zypper package manager..."
            zypper install -y iptables
            ;;
        void)
            echo "Using xbps package manager..."
            xbps-install -Sy iptables
            ;;
        *)
            echo "WARNING: Unknown distribution '$DISTRO' (family: '$DISTRO_LIKE')"
            echo ""
            echo "Please manually install the following packages:"
            echo "  Debian/Ubuntu: sudo apt install iptables"
            echo "  Fedora:        sudo dnf install iptables"
            echo "  Arch:          sudo pacman -S iptables"
            echo ""
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    echo "Dependencies installed"
}

# Check if files exist in current directory
check_files() {
    echo ""
    echo "Checking for required files..."
    
    if [ ! -f "$SCRIPT_DIR/proxyprism" ]; then
        echo "ERROR: proxyprism binary not found in $SCRIPT_DIR"
        exit 1
    fi
    
    echo "All files present"
}

# Install files
install_files() {
    echo ""
    echo "Installing proxyprism..."
    
    # Create directories if they don't exist
    mkdir -p /usr/local/bin /etc/proxyprism
    chmod 755 /etc/proxyprism
    
    # Copy binary
    echo "Installing proxyprism to /usr/local/bin..."
    cp "$SCRIPT_DIR/proxyprism" /usr/local/bin/
    chmod 755 /usr/local/bin/proxyprism

    # Install example config only if it does not already exist
    if [ -f "$SCRIPT_DIR/proxyprism.conf.example" ]; then
        if [ ! -f "/etc/proxyprism.conf" ]; then
            echo "Installing sample config to /etc/proxyprism.conf..."
            cp "$SCRIPT_DIR/proxyprism.conf.example" /etc/proxyprism.conf
            chmod 644 /etc/proxyprism.conf
            echo "Sample config installed. Edit /etc/proxyprism.conf to customize."
        else
            echo "/etc/proxyprism.conf already exists, not overwriting."
        fi
    fi
    
    echo "Files installed"
}

# Verify installation
verify_installation() {
    echo ""
    echo "Verifying installation..."
    
    # Check if binary is in PATH
    if command -v proxyprism &> /dev/null; then
        echo "proxyprism binary found in PATH"
    else
        echo "proxyprism binary not found in PATH"
        echo "  You may need to add /usr/local/bin to your PATH"
    fi
    
    # Final test - try to run --help
    if /usr/local/bin/proxyprism --help &>/dev/null; then
        echo "proxyprism executable is working"
    else
        echo "proxyprism may have issues"
    fi
}

# Main deployment
main() {
    detect_distro
    check_files
    install_dependencies
    install_files
    verify_installation
    
    echo ""
    echo "==================================="
    echo "Installation Complete!"
    echo "==================================="
    echo ""
    echo "You can now run proxyprism from anywhere:"
    echo "  sudo proxyprism --help"
    echo "  sudo proxyprism --check-config"
    echo "  sudo proxyprism  (uses /etc/proxyprism.conf)"
    echo ""
    echo "For cleanup after crash:"
    echo "  sudo proxyprism --cleanup"
    echo ""
}

main
