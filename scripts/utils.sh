#!/bin/bash

# Exit on error (but allow commands to continue when in CI mode)
if [[ "$1" != "--ci" ]]; then
  set -e
fi

# Define colors for output
export GREEN='\033[0;32m'
export RED='\033[0;31m'
export YELLOW='\033[0;33m'
export NC='\033[0m' # No Color

# Function to print section headers
print_header() {
  echo -e "\n${GREEN}======== $1 ========${NC}\n"
}

# Check if tools are installed, install if needed and not in CI mode
ensure_tool_installed() {
  local tool=$1
  local package=${2:-$tool}
  
  if ! command -v "$tool" &> /dev/null; then
    echo -e "${YELLOW}$tool not found${NC}"
    if [[ "$CI_MODE" == false ]]; then
      read -p "Install $tool? (y/n) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        pip install "$package"
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

# Determine if running in CI mode
detect_ci_mode() {
  if [[ "$1" == "--ci" ]]; then
    export CI_MODE=true
    echo "Running in CI mode"
  else
    export CI_MODE=false
  fi
}

# Create necessary directories if they don't exist
ensure_directories() {
  for dir in "$@"; do
    if [ ! -d "$dir" ]; then
      echo -e "${YELLOW}Creating directory: $dir${NC}"
      mkdir -p "$dir"
    fi
  done
}

# Prompt user for confirmation
confirm_action() {
  local message=$1
  local default=${2:-y}
  
  if [[ "$CI_MODE" == true ]]; then
    # Auto-confirm in CI mode
    return 0
  fi
  
  read -p "$message (y/n) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    return 0
  else
    return 1
  fi
}

# Log a message with a timestamp
log_message() {
  local level=$1
  local message=$2
  
  case $level in
    "INFO")
      echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}INFO${NC}: $message"
      ;;
    "WARNING")
      echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARNING${NC}: $message"
      ;;
    "ERROR")
      echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC}: $message"
      ;;
    *)
      echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $message"
      ;;
  esac
} 