#!/bin/bash

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Set Python path to ensure modules can be found
export PYTHONPATH=$(pwd)

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

function print_header() {
  echo -e "\n${GREEN}======== $1 ========${NC}\n"
}

function run_basic_tests() {
  print_header "Running Basic Tests"
  pytest "$@"
}

function run_coverage_tests() {
  print_header "Running Tests with Coverage"
  pytest --cov=app --cov-report=term-missing "$@"
}

function run_security_tests() {
  print_header "Running Security Tests"
  # Use bandit to check for security issues
  ensure_tool_installed bandit
  if command -v bandit &> /dev/null; then
    bandit -r app/
  fi
}

function run_lint() {
  print_header "Running Linting"
  ensure_tool_installed flake8
  if command -v flake8 &> /dev/null; then
    flake8 app/ tests/
  fi
}

function show_help() {
  echo "Usage: $0 [OPTIONS]"
  echo "Options:"
  echo "  --basic          Run basic tests"
  echo "  --coverage       Run tests with coverage"
  echo "  --security       Run security checks"
  echo "  --lint           Run linting"
  echo "  --all            Run all tests (default)"
  echo "  --ci             Run tests in CI mode (all tests with minimal output)"
  echo "  --help           Show this help message"
  echo ""
  echo "Additional arguments after -- are passed to pytest:"
  echo "  $0 --basic -- -xvs"
}

# Process command line arguments
detect_ci_mode "$@"

# Default is to run all tests
RUN_BASIC=false
RUN_COVERAGE=false
RUN_SECURITY=false
RUN_LINT=false

# If no args, run all tests
if [ $# -eq 0 ]; then
  RUN_BASIC=true
  RUN_COVERAGE=true
  RUN_SECURITY=true
  RUN_LINT=true
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --basic)
      RUN_BASIC=true
      shift
      ;;
    --coverage)
      RUN_COVERAGE=true
      shift
      ;;
    --security)
      RUN_SECURITY=true
      shift
      ;;
    --lint)
      RUN_LINT=true
      shift
      ;;
    --all)
      RUN_BASIC=true
      RUN_COVERAGE=true
      RUN_SECURITY=true
      RUN_LINT=true
      shift
      ;;
    --ci)
      # CI mode is already detected by detect_ci_mode
      RUN_BASIC=true
      RUN_COVERAGE=true
      RUN_SECURITY=true
      RUN_LINT=true
      shift
      ;;
    --help)
      show_help
      exit 0
      ;;
    --)
      shift
      PYTEST_ARGS="$@"
      break
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Ensure necessary directories exist
ensure_directories "logs" "flask_session"

# Run CI mode with minimal output
if [ "$CI_MODE" = true ]; then
  print_header "Running Tests in CI Mode"
  # Run all tests with minimal output
  pytest --cov=app --cov-report=xml ${PYTEST_ARGS}
  exit $?
fi

# Run selected test types
if [ "$RUN_BASIC" = true ]; then
  run_basic_tests ${PYTEST_ARGS}
fi

if [ "$RUN_COVERAGE" = true ]; then
  run_coverage_tests ${PYTEST_ARGS}
fi

if [ "$RUN_SECURITY" = true ]; then
  run_security_tests
fi

if [ "$RUN_LINT" = true ]; then
  run_lint
fi

log_message "INFO" "All requested tests completed!" 