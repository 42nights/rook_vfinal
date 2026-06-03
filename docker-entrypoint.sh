#!/bin/sh
# Rook container entrypoint. Routes the first arg to a subcommand so the image
# serves the app by default but can also run a one-shot PR scan in CI.
set -e
case "$1" in
  scan-pr)
    exec npx tsx scripts/scan-pr.ts
    ;;
  scan)
    shift
    exec npx tsx scripts/scan.ts "$@"
    ;;
  start | "")
    exec npm run start
    ;;
  *)
    exec "$@"
    ;;
esac
