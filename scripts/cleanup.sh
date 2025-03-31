#!/bin/bash

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# List of files to be removed
FILES_TO_REMOVE=(
  "README-SCSS.md"        # Consolidated into README.md
  "docs/DOCKER_GUIDE.md"  # Consolidated into deployment.md
  "app/logger.py"         # Consolidated into app/utils/logging.py
)

log_message "WARNING" "This script will remove redundant files that have been consolidated."
log_message "WARNING" "The following files will be removed:"

for file in "${FILES_TO_REMOVE[@]}"; do
  if [ -f "$file" ]; then
    echo -e "  - ${RED}$file${NC}"
  else
    echo -e "  - $file ${GREEN}(already removed)${NC}"
  fi
done

if confirm_action "Are you sure you want to continue?"; then
  # Remove files
  for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
      rm "$file"
      log_message "INFO" "Removed: $file"
    fi
  done

  log_message "INFO" "Cleanup complete!"
  log_message "WARNING" "Note: You may need to update any references to these files in other documentation."
else
  log_message "WARNING" "Operation cancelled."
  exit 1
fi 