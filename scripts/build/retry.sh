#!/bin/false

retry() {
  local command="$1"
  local retries=0

  until (( retries >= MAX_RETRIES )); do
    echo "Attempt $((retries + 1)) for command: $command"
    if eval "$command"; then
      echo "Command succeeded: $command"
      return 0
    fi
    echo "Command failed: $command. Retrying..."
    retries=$((retries + 1))
  done

  echo "All attempts failed for command: $command"
  return 1
}

export -f retry
