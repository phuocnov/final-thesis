#!/usr/bin/env bash
# Timestamp helper: print the current UTC time before/after you run a traffic
# tool, so you can paste accurate rows into labels.csv without doing date math.
# Millisecond precision so the end of a window doesn't clip the last requests.
# Usage: ./mark.sh "scan from laptop"
date -u +"%Y-%m-%dT%H:%M:%S.%3NZ  $*"
