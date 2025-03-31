#!/bin/bash

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Process command line arguments
detect_ci_mode "$@"

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to print section headers
function print_header() {
  echo -e "\n${GREEN}======== $1 ========${NC}\n"
}

# Check if running in CI mode (suppresses interactive prompts)
CI_MODE=false
if [[ "$1" == "--ci" ]]; then
  CI_MODE=true
  echo "Running in CI mode"
fi

# Check if tools are installed, install if needed and not in CI mode
function ensure_tool_installed() {
  local tool=$1
  local package=${2:-$tool}
  
  if ! command -v $tool &> /dev/null; then
    echo -e "${YELLOW}$tool not found${NC}"
    if [[ "$CI_MODE" == false ]]; then
      read -p "Install $tool? (y/n) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip install $package
      else
        echo -e "${YELLOW}Skipping $tool installation${NC}"
      fi
    else
      echo -e "${YELLOW}Skipping $tool installation in CI mode${NC}"
    fi
  else
    echo -e "${GREEN}$tool is installed${NC}"
  fi
}

# Install dependency checking tools if needed
print_header "Checking Dependency Tools"
ensure_tool_installed pip-audit
ensure_tool_installed safety
ensure_tool_installed pip-outdated pip-outdated

# Check for security vulnerabilities
print_header "Checking for Security Vulnerabilities"
if command -v pip-audit &> /dev/null; then
  log_message "INFO" "Running pip-audit..."
  pip-audit -r requirements.txt || true
elif command -v safety &> /dev/null; then
  log_message "INFO" "Running safety check..."
  safety check -r requirements.txt || true
else
  log_message "WARNING" "No security scanning tools available. Install pip-audit or safety."
fi

# Check for outdated dependencies
print_header "Checking for Outdated Dependencies"
if command -v pip-outdated &> /dev/null; then
  pip-outdated || true
else
  pip list --outdated || true
fi

# Check dependencies for compatibility issues
print_header "Checking Compatibility Constraints"
log_message "INFO" "Current Flask version requires Werkzeug 2.2.x"
log_message "INFO" "Flask-WTF 1.2.2 requires Werkzeug's url_encode function (removed in 2.3.0+)"

# Generate dependency graph
print_header "Generating Dependency Graph"
if command -v pipdeptree &> /dev/null; then
  pipdeptree -p Flask,Werkzeug,Flask-WTF || true
else
  log_message "WARNING" "pipdeptree not installed. Install with: pip install pipdeptree"
  if [[ "$CI_MODE" == false ]]; then
    if confirm_action "Install pipdeptree?"; then
      pip install pipdeptree
      pipdeptree -p Flask,Werkzeug,Flask-WTF
    fi
  fi
fi

# Generate a report file if in CI mode
if [[ "$CI_MODE" == true ]]; then
  print_header "Generating Dependency Report"
  REPORT_FILE="dependency_report.txt"
  
  echo "Dependency Report - $(date)" > $REPORT_FILE
  echo "===========================" >> $REPORT_FILE
  echo "" >> $REPORT_FILE
  
  echo "Known Vulnerabilities:" >> $REPORT_FILE
  if command -v pip-audit &> /dev/null; then
    pip-audit -r requirements.txt -f json | tee -a $REPORT_FILE
  elif command -v safety &> /dev/null; then
    safety check -r requirements.txt --json | tee -a $REPORT_FILE
  fi
  
  log_message "INFO" "Dependency report saved to $REPORT_FILE"
fi

log_message "INFO" "See docs/KNOWN_ISSUES.md for more information on security issues and constraints." 